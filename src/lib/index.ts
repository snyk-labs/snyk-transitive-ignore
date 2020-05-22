export {}

import 'source-map-support/register'
const args = require('minimist')(process.argv.slice(2))
import { readFileSync, writeFileSync } from 'fs'
import { Stream } from 'stream'

const IGNORE_FILE = ".snyk_ignore"

function readStream(stream: Stream, encoding = "utf8") {
    return new Promise((resolve, reject) => {
        let data = "";
        
        stream.on("data", chunk => data += chunk);
        stream.on("end", () => resolve(data));
        stream.on("error", error => reject(error));
    });
}

function checkIgnoreListMatch(ignoreItems: string[], directDep: string) {
    // check for two types of matches
    // 1. when version is not specified in the ignore entry
    // 2. when version is specified in the ignore entry

    for (const ignoreItem of ignoreItems) {
        // if ignoreItem contains an @ symbol, compare for equality to directDep
        if (ignoreItem.includes('@')) {
            if (ignoreItem == directDep) {
                console.log(`${ignoreItem} matches ${directDep}`)
                return true;
            }
        }
        else {
            if (directDep.startsWith(ignoreItem.concat('@'))) {
                console.log(`${ignoreItem} matches ${directDep}`)
                return true;
            }
        }
        // if ignoreItem does not contain an @symbol, compare for startsWith match
        // up to and including @ symbol (any version)
    }
}

function writeIgnoreEntry(vuln: string, path: string, expires: string, reason: string) {
    let writeString: string = "ignore:\n" +
        "  " + vuln + ":\n" +
        "    - '" + path + "':\n" + 
        "        reason: " + reason + "\n" + 
        "        expires: " + expires + "\n"
    
    
    writeFileSync(IGNORE_FILE, writeString, { flag: 'a' })
    
}


const snykTransitiveIgnore = async () => {
  var inputFile: string = ""
  var fullPath: string = ""

  if (args.f && typeof args.f !== 'boolean') {
    inputFile = args.f;
    var ignoreStrings: string[] = await readFileSync(inputFile).toString().split("\n");
    //console.log(ignoreStrings);
  }
  else {
    console.log('input file not specified');
  }
  
  await readStream(process.stdin).then(async function(data){
    const issues: any = JSON.parse(String(data))
    for await (const vuln of issues.vulnerabilities) {
      fullPath = ""

      console.log(`vuln id ${vuln.id}`)
      console.log(`from direct dep ${vuln.from[1]}`)

      for await(const from of vuln.from) {
          if (fullPath != "") {
            fullPath += ` > ${from}`
          }
          else {
              fullPath = `${from}`
          }
      }
      console.log(`full path ${fullPath}`)
      console.log(`is ${vuln.from[1]} in ignore list?`)
      if (checkIgnoreListMatch(ignoreStrings, vuln.from[1])) {
          await writeIgnoreEntry(vuln.id, vuln.from[1], "2100-01-01", "transitive ignore")
      }

    }
  })   
}

snykTransitiveIgnore()

