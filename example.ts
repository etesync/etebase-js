import * as Etebase from "./src/Etebase";

const args = process.argv.slice(2);

const username = args.shift();
const password = args.shift();
const serverUrl = args.shift();
const colUid = args.shift();

if (!username || !password || !serverUrl) {
  console.error("Help: ./example.ts USERNAME PASSWORD SERVER_URL [COLLECTION_UID]");
  process.exit(1);
}

(async () => {
  const etebase = await Etebase.Account.login(username, password, serverUrl);
  const colMgr = etebase.getCollectionManager();
  if (colUid) {
    const col = await colMgr.fetch(colUid);
    const itMgr = colMgr.getItemManager(col);
    const items = await itMgr.list();
    console.log(await col.getMeta());
    console.log("Item count:", items.data.length);
    for (const item of items.data) {
      console.log("UID:", item.uid);
      console.log(await item.getMeta());
    }
  } else {
    const collections = await colMgr.list();
    for (const col of collections.data) {
      console.log("UID:", col.uid);
      console.log(await col.getMeta());
    }
  }
  await etebase.logout();
})();
