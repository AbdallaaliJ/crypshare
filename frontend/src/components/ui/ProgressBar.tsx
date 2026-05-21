import React from 'react';
import './ProgressBar.css';

interface ProgressBarProps {
  progress: number;
  label?: string;
  status?: 'active' | 'success' | 'error';
}

export const ProgressBar: React.FC<ProgressBarProps> = ({ progress, label, status = 'active' }) => {
  const clampedProgress = Math.min(100, Math.max(0, progress));

  return (
    <div className="progress-container">
      {label && (
        <div className="progress-header flex-row justify-between w-full mb-2 text-sm text-muted">
          <span>{label}</span>
          <span>{Math.round(clampedProgress)}%</span>
        </div>
      )}
      <div className="progress-track">
        <div 
          className={`progress-fill progress-${status}`}
          style={{ width: `${clampedProgress}%` }}
        />
      </div>
    </div>
  );
};
