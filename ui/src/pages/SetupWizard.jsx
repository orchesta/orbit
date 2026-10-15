import { useState } from 'react';
import { useAuth } from '../context/auth';

export default function SetupWizard() {
  const { setup, setupTokenRequired } = useAuth();
  const [setupToken, setSetupToken] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    setLoading(true);
    try {
      await setup(email, password, displayName, setupToken);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 p-6 animate-in fade-in duration-700 select-none">
      <div className="w-full max-w-xl bg-white border border-slate-200 rounded-[3rem] p-12 shadow-2xl relative overflow-hidden group">
        <div className="absolute top-0 left-0 w-full h-1.5 bg-gradient-to-r from-indigo-500 via-purple-500 to-emerald-500 opacity-80"></div>
        
        <div className="text-center mb-10">
          <h1 className="text-5xl font-black text-slate-900 tracking-tighter mb-2">Welcome to Orbit</h1>
          <p className="text-slate-500 font-bold tracking-wide">Create your admin account to get started</p>
        </div>

        <div className="flex justify-between items-center mb-12 relative px-4">
          <div className="absolute top-[19px] left-0 w-full h-0.5 bg-slate-100 -z-0"></div>
          <div className="absolute top-[19px] left-0 w-[15%] h-0.5 bg-indigo-500 -z-0 shadow-[0_0_8px_rgba(99,102,241,0.3)]"></div>
          
          <div className="flex flex-col items-center gap-3 relative z-10">
            <div className="h-10 w-10 rounded-full bg-indigo-600 text-white flex items-center justify-center font-black shadow-lg shadow-indigo-100 border-4 border-white transition-all group-hover:scale-110">1</div>
            <span className="text-[10px] font-black text-indigo-600 uppercase tracking-[0.2em]">ADMIN</span>
          </div>
          <div className="flex flex-col items-center gap-3 relative z-10">
            <div className="h-10 w-10 rounded-full bg-slate-100 text-slate-400 flex items-center justify-center font-black border-4 border-white">2</div>
            <span className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em]">REPOS</span>
          </div>
          <div className="flex flex-col items-center gap-3 relative z-10">
            <div className="h-10 w-10 rounded-full bg-slate-100 text-slate-400 flex items-center justify-center font-black border-4 border-white">3</div>
            <span className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em]">SCAN</span>
          </div>
        </div>

        {error && (
          <div className="mb-8 p-4 bg-rose-50 border border-rose-100 rounded-2xl text-rose-600 text-sm font-black text-center animate-in slide-in-from-top-2 duration-300">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <label className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] ml-1">Display Name</label>
              <input 
                className="w-full h-12 px-5 bg-slate-50 border border-slate-100 rounded-xl text-slate-900 placeholder:text-slate-300 focus:border-indigo-500 focus:bg-white outline-none transition-all duration-300 font-bold shadow-sm" 
                placeholder="Admin"
                value={displayName} 
                onChange={e => setDisplayName(e.target.value)} 
                autoFocus 
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] ml-1">Email Address</label>
              <input 
                className="w-full h-12 px-5 bg-slate-50 border border-slate-100 rounded-xl text-slate-900 placeholder:text-slate-300 focus:border-indigo-500 focus:bg-white outline-none transition-all duration-300 font-bold shadow-sm" 
                type="email" 
                placeholder="admin@example.com"
                value={email} 
                onChange={e => setEmail(e.target.value)} 
                required 
              />
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <label className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] ml-1">Password</label>
              <input 
                className="w-full h-12 px-5 bg-slate-50 border border-slate-100 rounded-xl text-slate-900 placeholder:text-slate-300 focus:border-indigo-500 focus:bg-white outline-none transition-all duration-300 font-bold font-mono shadow-sm" 
                type="password" 
                placeholder="At least 8 chars"
                value={password} 
                onChange={e => setPassword(e.target.value)} 
                required 
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] ml-1">Confirm Secret</label>
              <input 
                className="w-full h-12 px-5 bg-slate-50 border border-slate-100 rounded-xl text-slate-900 placeholder:text-slate-300 focus:border-indigo-500 focus:bg-white outline-none transition-all duration-300 font-bold font-mono shadow-sm" 
                type="password" 
                placeholder="Repeat password"
                value={confirmPassword} 
                onChange={e => setConfirmPassword(e.target.value)} 
                required 
              />
            </div>
          </div>
          {setupTokenRequired && (
            <div className="space-y-2">
              <label className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] ml-1">Setup Token</label>
              <input
                className="w-full h-12 px-5 bg-slate-50 border border-slate-100 rounded-xl text-slate-900 placeholder:text-slate-300 focus:border-indigo-500 focus:bg-white outline-none transition-all duration-300 font-bold font-mono shadow-sm"
                type="password"
                placeholder="Value of ORBIT_SETUP_TOKEN"
                value={setupToken}
                onChange={e => setSetupToken(e.target.value)}
                required
              />
            </div>
          )}
          <button 
            className="w-full h-14 bg-emerald-600 hover:bg-emerald-700 text-white font-black rounded-2xl shadow-xl shadow-emerald-100 transition-all active:scale-95 flex items-center justify-center gap-3 text-lg mt-4 group/btn" 
            type="submit" 
            disabled={loading}
          >
            {loading ? (
              <span className="h-6 w-6 animate-spin rounded-full border-3 border-white border-t-transparent"></span>
            ) : (
              <>Complete Setup <span className="group-hover:translate-x-1 transition-transform">→</span></>
            )}
          </button>
        </form>
      </div>
    </div>
  );
}
