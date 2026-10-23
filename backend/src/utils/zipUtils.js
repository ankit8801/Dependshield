const yauzl = require('yauzl');
const fs = require('fs');
const path = require('path');

const MAX_UNCOMPRESSED_SIZE = process.env.MAX_UNCOMPRESSED_SIZE || 1024 * 1024 * 500; // 500MB
const MAX_FILE_COUNT = process.env.MAX_FILE_COUNT || 20000;
const MAX_FILE_SIZE = process.env.MAX_FILE_SIZE || 1024 * 1024 * 100; // 100MB per file

/**
 * Safely extracts a ZIP file to a destination directory.
 * Protects against Zip Slip and Zip Bombs.
 * @param {string} zipFilePath 
 * @param {string} extractDir 
 * @returns {Promise<void>}
 */
const extractZipSecurely = (zipFilePath, extractDir) => {
  return new Promise((resolve, reject) => {
    let totalUncompressedSize = 0;
    let fileCount = 0;

    yauzl.open(zipFilePath, { lazyEntries: true }, (err, zipfile) => {
      if (err) return reject(new Error('Invalid ZIP file'));

      zipfile.readEntry();

      zipfile.on('entry', (entry) => {
        // Increment file count
        fileCount++;
        if (fileCount > MAX_FILE_COUNT) {
          zipfile.close();
          return reject(new Error('Zip extraction failed: Too many files'));
        }

        // Prevent Zip Slip
        if (entry.fileName.includes('..') || entry.fileName.startsWith('/') || entry.fileName.startsWith('\\')) {
          zipfile.close();
          return reject(new Error('Zip extraction failed: Path traversal detected'));
        }

        const resolvedExtractDir = path.resolve(extractDir);
        const targetPath = path.resolve(extractDir, entry.fileName);
        
        // Ensure the resolved target path is strictly inside extractDir.
        // Use startsWith with the separator to prevent adjacent-directory bypass:
        //   e.g. extractDir=/tmp/foo, targetPath=/tmp/foobar/evil would incorrectly
        //   pass an indexOf === 0 check but correctly fail this one.
        const isInsideExtractDir =
          targetPath === resolvedExtractDir ||
          targetPath.startsWith(resolvedExtractDir + path.sep);

        if (!isInsideExtractDir) {
          zipfile.close();
          return reject(new Error('Zip extraction failed: Path traversal detected'));
        }

        if (/\/$/.test(entry.fileName)) {
          // It's a directory
          fs.mkdir(targetPath, { recursive: true }, (mkdirErr) => {
            if (mkdirErr) return reject(mkdirErr);
            zipfile.readEntry();
          });
        } else {
          // Check uncompressed size from header if available
          if (entry.uncompressedSize > MAX_FILE_SIZE) {
             zipfile.close();
             return reject(new Error('Zip extraction failed: Individual file size exceeded'));
          }
          
          totalUncompressedSize += entry.uncompressedSize;
          if (totalUncompressedSize > MAX_UNCOMPRESSED_SIZE) {
            zipfile.close();
            return reject(new Error('Zip extraction failed: Total uncompressed size exceeded'));
          }

          // Ensure parent directory exists
          fs.mkdir(path.dirname(targetPath), { recursive: true }, (mkdirErr) => {
            if (mkdirErr) return reject(mkdirErr);

            zipfile.openReadStream(entry, (streamErr, readStream) => {
              if (streamErr) return reject(streamErr);

              const writeStream = fs.createWriteStream(targetPath);
              let bytesWritten = 0;

              readStream.on('data', (chunk) => {
                 bytesWritten += chunk.length;
                 // Additional safety check while reading
                 if (bytesWritten > MAX_FILE_SIZE) {
                   readStream.destroy();
                   zipfile.close();
                   reject(new Error('Zip extraction failed: File size exceeded during read'));
                 }
              });

              readStream.on('error', (err) => {
                reject(err);
              });
              
              writeStream.on('error', (err) => {
                reject(err);
              });

              readStream.on('end', () => {
                zipfile.readEntry();
              });

              readStream.pipe(writeStream);
            });
          });
        }
      });

      zipfile.on('end', () => {
        resolve();
      });

      zipfile.on('error', (err) => {
        reject(err);
      });
    });
  });
};

module.exports = {
  extractZipSecurely
};
