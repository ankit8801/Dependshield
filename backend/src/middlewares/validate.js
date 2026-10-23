const { ZodError } = require('zod');

const validate = (schema) => (req, res, next) => {
  try {
    schema.parse({
      body: req.body,
      query: req.query,
      params: req.params,
    });
    next();
  } catch (error) {
    if (error instanceof ZodError) {
      return res.status(400).json({
        error: {
          message: 'Validation Error',
          details: error.errors
        }
      });
    }
    next(error);
  }
};

module.exports = validate;
