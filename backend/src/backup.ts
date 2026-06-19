import { backupDatabase, closeDatabase } from "./database";

async function main() {
  const destination = await backupDatabase();
  console.log(`Database backup written to ${destination}`);
}

main()
  .catch((err) => {
    console.error("Database backup failed.", err);
    process.exitCode = 1;
  })
  .finally(async () => {
    await closeDatabase();
  });
