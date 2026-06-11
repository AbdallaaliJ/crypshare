import { createContext } from 'react';

export interface LogContextProps {
  logs: string[];
  addLog: (msg: string) => void;
  clearLogs: () => void;
}

export const LogContext = createContext<LogContextProps | undefined>(undefined);
