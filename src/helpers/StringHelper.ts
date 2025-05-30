// Error: Could not find a declaration file for module ../helpers/EventHelper.
// /Users/nilsbaumgartner/Documents/GitHub/rocket-meals/backend/Backend/directusExtensions/directus-extension-rocket-meals-bundle/src/helpers/EventHelper.js

// create declaration file for module
export class StringHelper{

    // also be able to replace "*" with "WILDCARD_REPLACEMENT"
    static replaceAll(str: string, find: string, replace: string) {
        return str.replace(new RegExp(find, 'g'), replace);
    }

}