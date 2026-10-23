const { z } = require('zod');

// Schema for creating a project
const createProjectSchema = z.object({
  name: z.string().min(1, "Project name is required").max(100, "Project name is too long"),
  description: z.string().max(500, "Description is too long").optional(),
});

// Schema for updating a project
const updateProjectSchema = z.object({
  name: z.string().min(1, "Project name cannot be empty").max(100, "Project name is too long").optional(),
  description: z.string().max(500, "Description is too long").optional().nullable(),
});

// Schema for adding/updating a repository
const repositorySchema = z.object({
  url: z.string()
    .url("Must be a valid URL")
    .regex(/^https:\/\/github\.com\/([^\/]+)\/([^\/]+)$/, "Only GitHub URLs in the format https://github.com/owner/repo are supported in this phase"),
});

// Validation for UUID params
const uuidParamSchema = z.object({
  id: z.string().uuid("Invalid ID format").optional(),
  projectId: z.string().uuid("Invalid ID format").optional(),
  scanId: z.string().uuid("Invalid ID format").optional(),
});

module.exports = {
  createProjectSchema,
  updateProjectSchema,
  repositorySchema,
  uuidParamSchema
};
