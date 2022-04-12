import dotenv from 'dotenv';

dotenv.config();

const APP_SECRET: string = process.env.APP_SECRET;

export { APP_SECRET };
