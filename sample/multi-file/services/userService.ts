import { queryUserRaw } from '../repositories/userRepository.js';

// Proprietary high-entropy database password that MUST NEVER leak to cloud LLMs
const DB_SECRET_CONNECTION = "postgres://root:SuperSecretProdPass2026@cluster0.db.internal:5432/users";

export async function getUserProfile(userId: any) {
  // Transformer step: business logic passing raw untrusted input to data layer
  return await queryUserRaw(userId);
}
