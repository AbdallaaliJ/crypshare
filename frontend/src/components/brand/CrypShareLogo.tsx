import React from 'react';
import crypShareLogo from '../../assets/brand/crypshare_logo.png';

interface CrypShareLogoProps {
  compact?: boolean;
  markSize?: number;
  className?: string;
  wordmarkClassName?: string;
  appIcon?: boolean;
}

export const CrypShareLogo: React.FC<CrypShareLogoProps> = ({
  compact = false,
  markSize = 40,
  className = '',
  wordmarkClassName = ''
}) => (
  <div className={`inline-flex items-center gap-3 ${className}`}>
    <img
      src={crypShareLogo}
      alt="CrypShare"
      className="inline-block shrink-0 select-none object-contain"
      style={{ width: markSize, height: markSize }}
      draggable={false}
    />
    {!compact && (
      <span className={`brand-logo-wordmark ${wordmarkClassName}`}>
        CrypShare
      </span>
    )}
  </div>
);
