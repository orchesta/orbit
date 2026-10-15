# Orbit UI

React 19 + Vite + Tailwind 4. Data loading goes through `src/services/api.js` and @tanstack/react-query.

```bash
npm install
npm run dev     # http://localhost:3000, proxies /api to http://localhost:8080
npm test        # vitest + Testing Library
npm run lint
npm run build   # output in dist/, served by the Go server
```
