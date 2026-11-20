import { build } from 'esbuild';
await build({entryPoints:['app.jsx'], bundle:true, jsx:'automatic', platform:'browser', format:'esm',
  define:{'process.env.NODE_ENV':'"production"'}, outfile:'../src/main/resources/static/bff-app.js', minify:true});
