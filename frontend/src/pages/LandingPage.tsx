import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, Lock, Zap } from 'lucide-react';

export const LandingPage: React.FC = () => {
  return (
    <div className="flex flex-col items-center justify-center text-center max-w-4xl mx-auto py-16 px-4 animate-in fade-in duration-700">
      {/* Premium Badge */}
      <div className="inline-flex items-center gap-2 bg-cyan-500/10 border border-cyan-500/20 px-4 py-1.5 rounded-full text-[11px] font-bold text-cyan-400 uppercase tracking-widest mb-8 shadow-[0_0_15px_rgba(34,211,238,0.05)]">
        <Shield className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
        The Future of Secure File Sharing
      </div>
      
      {/* Title */}
      <h1 className="text-4xl md:text-6xl font-extrabold tracking-tight text-white mb-6 leading-tight max-w-3xl">
        Uncompromised{' '}
        <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-indigo-400 to-purple-400 animate-pulse">
          Zero-Knowledge
        </span>{' '}
        Protocol
      </h1>
      
      {/* Description */}
      <p className="text-slate-400 text-base md:text-lg max-w-2xl mx-auto mb-12 leading-relaxed">
        Share files with absolute certainty. Our servers operate completely blind using X3DH key agreement and ECDSA signatures. We never see your password, and we can never decrypt your files.
      </p>
      
      {/* Buttons */}
      <div className="flex flex-col sm:flex-row gap-4 justify-center items-center w-full max-w-md mx-auto mb-20">
        <Link 
          to="/register" 
          className="w-full sm:w-auto px-8 py-4 bg-cyan-500 hover:bg-cyan-400 text-slate-950 rounded-xl font-bold transition-all hover:scale-[1.02] active:scale-95 shadow-[0_0_30px_rgba(34,211,238,0.2)] text-center text-sm"
        >
          Start Sharing Securely
        </Link>
        <a 
          href="https://github.com" 
          target="_blank" 
          rel="noreferrer" 
          className="w-full sm:w-auto px-8 py-4 bg-white/5 hover:bg-white/10 text-white border border-white/10 rounded-xl font-bold transition-all hover:scale-[1.02] active:scale-95 text-center text-sm"
        >
          View Documentation
        </a>
      </div>
      
      {/* Feature Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-left w-full">
        {/* Card 1 */}
        <div className="bg-slate-900/20 backdrop-blur-md border border-white/5 rounded-3xl p-8 hover:border-white/10 hover:bg-white/5 transition-all duration-300 group">
          <div className="w-12 h-12 bg-cyan-500/10 rounded-2xl flex items-center justify-center border border-cyan-500/20 mb-6 group-hover:scale-110 transition-transform">
            <Shield className="text-cyan-400" size={24} />
          </div>
          <h3 className="text-white text-lg font-bold mb-2">X3DH Protocol</h3>
          <p className="text-slate-400 text-xs leading-relaxed">
            Extended Triple Diffie-Hellman guarantees Perfect Forward Secrecy for all file exchanges.
          </p>
        </div>

        {/* Card 2 */}
        <div className="bg-slate-900/20 backdrop-blur-md border border-white/5 rounded-3xl p-8 hover:border-white/10 hover:bg-white/5 transition-all duration-300 group">
          <div className="w-12 h-12 bg-purple-500/10 rounded-2xl flex items-center justify-center border border-purple-500/20 mb-6 group-hover:scale-110 transition-transform">
            <Lock className="text-purple-400" size={24} />
          </div>
          <h3 className="text-white text-lg font-bold mb-2">AES-GCM 256</h3>
          <p className="text-slate-400 text-xs leading-relaxed">
            Military-grade symmetric encryption chunked perfectly for massive binary files.
          </p>
        </div>

        {/* Card 3 */}
        <div className="bg-slate-900/20 backdrop-blur-md border border-white/5 rounded-3xl p-8 hover:border-white/10 hover:bg-white/5 transition-all duration-300 group">
          <div className="w-12 h-12 bg-emerald-500/10 rounded-2xl flex items-center justify-center border border-emerald-500/20 mb-6 group-hover:scale-110 transition-transform">
            <Zap className="text-emerald-400" size={24} />
          </div>
          <h3 className="text-white text-lg font-bold mb-2">ECDSA Verified</h3>
          <p className="text-slate-400 text-xs leading-relaxed">
            Every payload is mathematically signed by the sender, completely eliminating impersonation.
          </p>
        </div>
      </div>
    </div>
  );
};
