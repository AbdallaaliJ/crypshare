import React, { useState, type ReactNode } from 'react';
import { LogContext } from './LogContextBase';

export const LogProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [logs, setLogs] = useState<string[]>(['> Protocol Layer Ready.']);

  const addLog = (msg: string) => {
    setLogs((prev) => [...prev, `> ${msg}`]);
  };

  const clearLogs = () => {
    setLogs(['> Protocol Layer Ready.']);
  };

  return (
    <LogContext.Provider value={{ logs, addLog, clearLogs }}>
      {children}
    </LogContext.Provider>
  );
};
