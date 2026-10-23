const projectService = require('../services/projectService');
const { createProjectSchema, updateProjectSchema, repositorySchema } = require('../validators/projectSchemas');

const createProject = async (req, res, next) => {
  try {
    const validatedData = createProjectSchema.parse(req.body);
    const project = await projectService.createProject(req.user.sub, validatedData);
    res.status(201).json({ data: project });
  } catch (error) {
    next(error);
  }
};

const getProjects = async (req, res, next) => {
  try {
    const projects = await projectService.getProjectsByUser(req.user.sub);
    res.status(200).json({ data: projects });
  } catch (error) {
    next(error);
  }
};

const getProject = async (req, res, next) => {
  try {
    const { id } = req.params;
    const project = await projectService.getProjectById(req.user.sub, id);
    
    if (!project) {
      return res.status(404).json({ error: { message: 'Project not found' } });
    }
    
    res.status(200).json({ data: project });
  } catch (error) {
    next(error);
  }
};

const updateProject = async (req, res, next) => {
  try {
    const { id } = req.params;
    const validatedData = updateProjectSchema.parse(req.body);
    const project = await projectService.updateProject(req.user.sub, id, validatedData);
    
    if (!project) {
      return res.status(404).json({ error: { message: 'Project not found' } });
    }
    
    res.status(200).json({ data: project });
  } catch (error) {
    next(error);
  }
};

const deleteProject = async (req, res, next) => {
  try {
    const { id } = req.params;
    const success = await projectService.deleteProject(req.user.sub, id);
    
    if (!success) {
      return res.status(404).json({ error: { message: 'Project not found' } });
    }
    
    res.status(200).json({ message: 'Project deleted successfully' });
  } catch (error) {
    next(error);
  }
};

const upsertRepository = async (req, res, next) => {
  try {
    const { id } = req.params;
    const validatedData = repositorySchema.parse(req.body);
    const repository = await projectService.upsertRepository(req.user.sub, id, validatedData.url);
    
    if (!repository) {
      return res.status(404).json({ error: { message: 'Project not found' } });
    }
    
    res.status(200).json({ data: repository });
  } catch (error) {
    next(error);
  }
};

const deleteRepository = async (req, res, next) => {
  try {
    const { id } = req.params;
    const success = await projectService.deleteRepository(req.user.sub, id);
    
    if (!success) {
      return res.status(404).json({ error: { message: 'Project not found' } });
    }
    
    res.status(200).json({ message: 'Repository deleted successfully' });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  createProject,
  getProjects,
  getProject,
  updateProject,
  deleteProject,
  upsertRepository,
  deleteRepository
};
