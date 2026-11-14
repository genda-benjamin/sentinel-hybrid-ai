// Mock database client
const db = {
  query: async (sql: string) => { return [{ id: 1, name: 'Alice' }]; }
};

export async function queryUserRaw(rawId: any) {
  // SINK (CWE-89): Vulnerable dynamic SQL query string concatenation
  return await db.query("SELECT * FROM users WHERE id = " + rawId);
}
