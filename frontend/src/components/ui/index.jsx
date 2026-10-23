export const Spinner = () => (
  <div className="flex items-center gap-2" style={{ color: 'var(--neutral)', padding: '1rem' }}>
    <svg className="animate-spin" viewBox="0 0 24 24" fill="none" style={{ width: '20px', height: '20px', animation: 'spin 1s linear infinite' }}>
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" strokeDasharray="32" strokeDashoffset="16" />
      <path d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" fill="currentColor" />
    </svg>
    <span className="text-sm font-medium">Loading...</span>
    <style>{`
      @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
    `}</style>
  </div>
);

export const Badge = ({ children, variant = 'neutral' }) => {
  return (
    <span className={`badge badge-${variant}`}>
      {children}
    </span>
  );
};

export const Alert = ({ type = 'info', title, children }) => {
  const styles = {
    danger: { bg: 'var(--danger-bg)', border: 'var(--danger-border)', color: 'var(--danger)' },
    warning: { bg: 'var(--warning-bg)', border: 'var(--warning-border)', color: 'var(--warning)' },
    success: { bg: 'var(--success-bg)', border: 'var(--success-border)', color: 'var(--success)' },
    info: { bg: 'var(--info-bg)', border: 'var(--info-border)', color: 'var(--info)' }
  };
  const s = styles[type] || styles.info;
  
  return (
    <div style={{
      backgroundColor: s.bg,
      border: `1px solid ${s.border}`,
      color: 'var(--text-h)',
      padding: '1rem',
      borderRadius: '8px',
      marginBottom: '1rem',
      display: 'flex',
      flexDirection: 'column',
      gap: '0.25rem'
    }}>
      {title && <div style={{ color: s.color, fontWeight: 600, fontSize: '0.875rem' }}>{title}</div>}
      <div style={{ fontSize: '0.875rem', lineHeight: 1.5 }}>
        {children}
      </div>
    </div>
  );
};
