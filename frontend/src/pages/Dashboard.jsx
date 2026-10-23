import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate, Link } from 'react-router-dom';
import { projectApi } from '../api/client';

const Dashboard = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [projects, setProjects] = useState([]);
  const [loading, setLoading] = useState(true);
  
  const [showCreate, setShowCreate] = useState(false);
  const [newProjectName, setNewProjectName] = useState('');
  const [newProjectDesc, setNewProjectDesc] = useState('');

  const fetchProjects = async () => {
    try {
      const res = await projectApi.getProjects();
      setProjects(res.data.data);
    } catch (error) {
      console.error('Failed to load projects', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProjects();
  }, []);

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const handleCreateProject = async (e) => {
    e.preventDefault();
    try {
      await projectApi.createProject({ name: newProjectName, description: newProjectDesc });
      setShowCreate(false);
      setNewProjectName('');
      setNewProjectDesc('');
      fetchProjects();
    } catch (error) {
      alert('Error creating project: ' + (error.response?.data?.error?.message || 'Unknown error'));
    }
  };

  return (
    <div style={styles.container}>
      <header style={styles.header}>
        <h1>DependShield</h1>
        <div style={styles.userInfo}>
          <span>{user?.email}</span>
          <button onClick={handleLogout} className="btn btn-secondary">Logout</button>
        </div>
      </header>
      
      <main style={styles.main}>
        <div style={styles.contentHeader}>
          <h2>Your Projects</h2>
          <button onClick={() => setShowCreate(!showCreate)} className="btn btn-primary">
            {showCreate ? 'Cancel' : '+ New Project'}
          </button>
        </div>

        {showCreate && (
          <div style={styles.createFormCard}>
            <h3>Create New Project</h3>
            <form onSubmit={handleCreateProject} style={styles.form}>
              <input
                type="text"
                placeholder="Project Name"
                value={newProjectName}
                onChange={(e) => setNewProjectName(e.target.value)}
                required
                className="input"
                style={{ flex: 1 }}
              />
              <input
                type="text"
                placeholder="Description (optional)"
                value={newProjectDesc}
                onChange={(e) => setNewProjectDesc(e.target.value)}
                className="input"
                style={{ flex: 1 }}
              />
              <button type="submit" className="btn btn-primary">Create</button>
            </form>
          </div>
        )}

        {loading ? (
          <div className="flex items-center justify-center" style={{ minHeight: '200px' }}>
            <div style={{ color: 'var(--neutral)' }}>Loading projects...</div>
          </div>
        ) : projects.length === 0 ? (
          <div style={styles.emptyState}>
            <p>You have no projects yet.</p>
            <button onClick={() => setShowCreate(true)} className="btn btn-primary" style={{ marginTop: '1rem' }}>Create your first project</button>
          </div>
        ) : (
          <div style={styles.grid}>
            {projects.map(project => (
              <Link to={`/projects/${project.id}`} key={project.id} style={styles.projectCard}>
                <h3>{project.name}</h3>
                <p style={styles.projectDesc}>{project.description || 'No description'}</p>
                <div style={styles.projectMeta}>
                  <small>Repository: {project.repository ? 'Linked' : 'None'}</small>
                  <small>Scans: {project._count?.scans || 0}</small>
                </div>
              </Link>
            ))}
          </div>
        )}
      </main>
    </div>
  );
};

const styles = {
  container: { minHeight: '100vh', display: 'flex', flexDirection: 'column', backgroundColor: 'var(--bg)' },
  header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1rem 2rem', backgroundColor: 'var(--code-bg)', borderBottom: '1px solid var(--border)' },
  userInfo: { display: 'flex', alignItems: 'center', gap: '1rem' },
  logoutButton: { padding: '0.5rem 1rem', backgroundColor: 'transparent', border: '1px solid var(--border)', borderRadius: '4px', color: 'var(--text-h)', cursor: 'pointer' },
  primaryButton: { padding: '0.5rem 1rem', backgroundColor: 'var(--accent)', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer', fontWeight: 'bold' },
  main: { flex: 1, padding: '2rem', maxWidth: '1000px', margin: '0 auto', width: '100%' },
  contentHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' },
  createFormCard: { backgroundColor: 'var(--code-bg)', padding: '1.5rem', borderRadius: '8px', marginBottom: '2rem', border: '1px solid var(--border)' },
  form: { display: 'flex', gap: '1rem', marginTop: '1rem', alignItems: 'center', flexWrap: 'wrap' },
  input: { padding: '0.5rem', borderRadius: '4px', border: '1px solid var(--border)', flex: 1, backgroundColor: 'var(--bg)', color: 'var(--text-h)' },
  emptyState: { textAlign: 'center', padding: '3rem', backgroundColor: 'var(--code-bg)', borderRadius: '8px', border: '1px dashed var(--border)' },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '1.5rem' },
  projectCard: { textDecoration: 'none', color: 'inherit', display: 'flex', flexDirection: 'column', backgroundColor: 'var(--code-bg)', padding: '1.5rem', borderRadius: '8px', border: '1px solid var(--border)', transition: 'transform 0.2s, box-shadow 0.2s', cursor: 'pointer', boxShadow: 'var(--shadow)' },
  projectDesc: { color: 'var(--text)', marginTop: '0.5rem', flex: 1 },
  projectMeta: { display: 'flex', justifyContent: 'space-between', marginTop: '1.5rem', color: 'var(--text)', borderTop: '1px solid var(--border)', paddingTop: '1rem' }
};

export default Dashboard;
