import { createContext } from 'react';

export type ToastType = 'success' | 'error' | 'info';

export interface ToastContextProps {
  showToast: (message: string, type?: ToastType) => void;
}

export const ToastContext = createContext<ToastContextProps | undefined>(undefined);
