export {}

import 'source-map-support/register'
const args = require('minimist')(process.argv.slice(2))
import { readFileSync } from 'fs';
import { Stream } from 'stream';


function readStream(stream: Stream, encoding = "utf8") {
    return new Promise((resolve, reject) => {
        let data = "";
        
        stream.on("data", chunk => data += chunk);
        stream.on("end", () => resolve(data));
        stream.on("error", error => reject(error));
    });
}

function checkIgnoreListMatch()

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
      checkIgnoreListMatch(ignoreStrings, vuln.from[1])
    }
  })   
}


snykTransitiveIgnore()

