// nanoid is best, but it is not available in nodejs
import ShortUniqueId from 'short-unique-id'; // is slow
//import { v4 as uuidv4 } from 'uuid';
//import baseX from 'base-x';

//const BASE62_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
//const base62 = baseX(BASE62_ALPHABET);

// Function to generate UUID and encode it in Base62 to match NanoID output
//function uuidBase62(size: number): string {
//    let encoded = '';
//    while (encoded.length < size) {
//        encoded += base62.encode(Buffer.from(uuidv4().replace(/-/g, ''), 'hex'));
//    }
//    return encoded.slice(0, size); // Ensure exactly 64 chars
//}

export class NanoidHelper {
    public static async getNanoid(size: number): Promise<string> {
        // old short-unique-id is slow
        const uid = new ShortUniqueId({ length: size });
        return uid.randomUUID(size);


        //Error: crypto.getRandomValues() not supported. See https://github.com/uuidjs/uuid#getrandomvalues-not-supported
        //    swosy-rocket-meals-directus-5         |     at file:///directus/extensions/directus-extension-rocket-meals-bundle/dist/api.js?t=1741708395377:18:50438
        //    swosy-rocket-meals-directus-5         |     at oh (file:///directus/extensions/directus-extension-rocket-meals-bundle/dist/api.js?t=1741708395377:18:50609)
        //swosy-rocket-meals-directus-5         |     at file:///directus/extensions/directus-extension-rocket-meals-bundle/dist/api.js?t=1741708395377:18:52917
        //    swosy-rocket-meals-directus-5         |     at sh.getNanoid (file:///directus/extensions/directus-extension-rocket-meals-bundle/dist/api.js?t=1741708395377:18:52967)
        //swosy-rocket-meals-directus-5         |     at file:///directus/extensions/directus-extension-rocket-meals-bundle/dist/api.js?t=1741708395377:557:639520
        //    swosy-rocket-meals-directus-5         |     at file:///directus/extensions/directus-extension-rocket-meals-bundle/dist/api.js?t=1741708395377:557:639828
        //    swosy-rocket-meals-directus-5         |     at process.processTicksAndRejections (node:internal/process/task_queues:95:5)
        //let id = uuidBase62(size);
        //return id;
    }
}