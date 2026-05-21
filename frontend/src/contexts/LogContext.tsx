import React, { createContext, useContext, useState, type ReactNode } from 'react';

interface LogContextProps {
  logs: string[];
  addLog: (msg: string) => void;
  clearLogs: () => void;
}

const LogContext = createContext<LogContextProps | undefined>(undefined);

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

export const useLogContext = () => {
  const context = useContext(LogContext);
  if (!context) {
    throw new Error('useLogContext must be used within a LogProvider');
  }
  return context;
};
