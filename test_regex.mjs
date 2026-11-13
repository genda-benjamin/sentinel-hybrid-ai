const regex = /(?:[a-zA-Z0-9_]*(?:password|secret|passwd|token|pass))\s*[:=]\s*["']([^"'\r\n]{6,128})["']/gi;
const code = 'const dbPass = "SuperSecretDBPassword!99";';
console.log('Matches:', code.match(regex));
console.log('Test:', regex.test(code));
console.log('Captured:');
code.replace(regex, (match, captured) => {
  console.log('match:', match);
  console.log('captured:', captured);
  return 'REPLACED';
});
