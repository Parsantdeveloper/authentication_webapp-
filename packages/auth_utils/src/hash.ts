 
import bcrypt from 'bcrypt';
import { AppError } from '@repo/errors';
export const hashPassword = async (password: string): Promise<string> => {
  try {
     const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds); 
  } catch (error) {
    throw new AppError("Failed to hash password",500);
  }

};

export const comparePassword = async (password: string, hash: string): Promise<boolean> => {
  try {
    return await bcrypt.compare(password, hash);
  } catch (error) {
    throw new AppError("Failed to compare password",500);
  }
};

export const hashRefreshToken = async (token: string): Promise<string> => {
  try {
    const saltRounds = 10;
    return await bcrypt.hash(token, saltRounds);
  } catch (error) {
    throw new AppError("Failed to hash refresh token",500);
  }
};

export const compareRefreshToken = async (token: string, hash: string): Promise<boolean> => {
  try {
    return await bcrypt.compare(token, hash);
  } catch (error) {
    throw new AppError("Failed to compare refresh token",500);
  }
};
