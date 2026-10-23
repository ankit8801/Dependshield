const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const createProject = async (userId, data) => {
  return prisma.project.create({
    data: {
      userId,
      name: data.name,
      description: data.description,
    },
    include: {
      repository: true,
      scans: {
        orderBy: { createdAt: 'desc' },
        take: 1,
      },
      _count: {
        select: { scans: true }
      }
    }
  });
};

const getProjectsByUser = async (userId) => {
  return prisma.project.findMany({
    where: { userId },
    include: {
      repository: true,
      scans: {
        orderBy: { createdAt: 'desc' },
        take: 1,
      },
      _count: {
        select: { scans: true }
      }
    },
    orderBy: { createdAt: 'desc' }
  });
};

const getProjectById = async (userId, projectId) => {
  const project = await prisma.project.findUnique({
    where: { id: projectId },
    include: {
      repository: true,
      scans: {
        orderBy: { createdAt: 'desc' },
        take: 1,
      },
      _count: {
        select: { scans: true }
      }
    }
  });

  if (!project || project.userId !== userId) {
    return null;
  }

  return project;
};

const updateProject = async (userId, projectId, data) => {
  // Authorization check
  const existing = await prisma.project.findUnique({ where: { id: projectId } });
  if (!existing || existing.userId !== userId) {
    return null;
  }

  return prisma.project.update({
    where: { id: projectId },
    data,
    include: {
      repository: true,
      scans: {
        orderBy: { createdAt: 'desc' },
        take: 1,
      }
    }
  });
};

const deleteProject = async (userId, projectId) => {
  // Authorization check
  const existing = await prisma.project.findUnique({ where: { id: projectId } });
  if (!existing || existing.userId !== userId) {
    return false; // indicating not found or unauthorized
  }

  await prisma.project.delete({
    where: { id: projectId }
  });

  return true;
};

// Repository operations
const upsertRepository = async (userId, projectId, url) => {
  // Authorization check
  const existing = await prisma.project.findUnique({ where: { id: projectId } });
  if (!existing || existing.userId !== userId) {
    return null;
  }

  return prisma.repository.upsert({
    where: { projectId },
    update: { url, type: 'GITHUB' },
    create: {
      projectId,
      url,
      type: 'GITHUB'
    }
  });
};

const deleteRepository = async (userId, projectId) => {
  // Authorization check
  const existing = await prisma.project.findUnique({ where: { id: projectId } });
  if (!existing || existing.userId !== userId) {
    return false;
  }

  try {
    await prisma.repository.delete({
      where: { projectId }
    });
    return true;
  } catch (error) {
    // If it doesn't exist, it's fine
    if (error.code === 'P2025') return true; 
    throw error;
  }
};

module.exports = {
  createProject,
  getProjectsByUser,
  getProjectById,
  updateProject,
  deleteProject,
  upsertRepository,
  deleteRepository
};
