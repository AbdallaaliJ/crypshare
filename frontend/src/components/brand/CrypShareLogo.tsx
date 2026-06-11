import React from 'react';

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
  wordmarkClassName = '',
  appIcon = false
}) => {
  const gradientId = `crypshare-logo-${React.useId().replace(/[^a-zA-Z0-9_-]/g, '')}`;

  return (
    <div className={`inline-flex items-center gap-3 ${className}`}>
      <svg
        width={markSize}
        height={markSize}
        viewBox="0 0 96 96"
        role="img"
        aria-label="CrypShare identity signature logo"
        className="shrink-0"
      >
        <defs>
          <linearGradient id={gradientId} x1="23" y1="86" x2="75" y2="12" gradientUnits="userSpaceOnUse">
            <stop stopColor="#0052FF" />
            <stop offset="0.5" stopColor="#00C2FF" />
            <stop offset="1" stopColor="#00D69F" />
          </linearGradient>
        </defs>

        {appIcon && (
          <rect
            x="6"
            y="6"
            width="84"
            height="84"
            rx="24"
            className="brand-app-icon-surface"
          />
        )}

        <g transform={appIcon ? 'translate(9 9) scale(0.82)' : undefined}>
          <g
            fill="none"
            stroke={`url(#${gradientId})`}
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth="5.2"
          >
            <path d="M18 48c0-22 16-36 35-36 15 0 27 8 34 21" />
            <path d="M27 48c0-16 11-27 26-27 11 0 20 6 25 16" />
            <path d="M36 47c0-10 7-18 17-18 8 0 14 4 17 11" />
            <path d="M45 46c0-5 4-9 9-9 4 0 8 2 10 6" />

            <path d="M64 53c-4-5-12-7-18-10-4-2-5-5-3-8" />
            <path d="M33 54c4 6 11 10 19 10 8 0 14-4 14-10 0-6-5-9-15-13" />
            <path d="M24 63c5 14 17 23 31 23 14 0 25-8 27-21" />
            <path d="M16 59c2 21 17 34 38 34" />

            <path d="M35 69c5 7 12 10 20 10 8 0 14-4 14-10 0-5-3-8-10-11" opacity="0.88" />
            <path d="M45 70c3 3 7 5 12 5 4 0 7-2 8-5" opacity="0.82" />
            <path d="M52 47c4 3 10 4 13 8" opacity="0.78" />

            <path d="M19 36c5-19 19-31 37-31" opacity="0.68" />
            <path d="M83 45c-1-19-14-34-32-38" opacity="0.68" />
            <path d="M87 56c0 22-15 36-36 36" opacity="0.68" />
          </g>
        </g>
      </svg>

      {!compact && (
        <span className={`brand-logo-wordmark ${wordmarkClassName}`}>
          CrypShare
        </span>
      )}
    </div>
  );
};
