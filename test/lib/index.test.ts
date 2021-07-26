import { doesNotReject } from "assert";
import { readFileSync } from "fs";
//const index = require("../../src/lib/index");

import { checkIgnoreListMatch } from "../../src/lib/index";

// var assert = require("assert");
// var _ = require("lodash");
var testPackagesFilename = "fixtures/sample-packages-to-ignore.list";
var testVersionMatchFromDependency =
  "org.springframework:spring-context@3.2.6.RELEASE";
var testPackageMatchFromDependency = "c3p0:c3p0@0.9.1.2";
var testWildcardMatchFromDependency =
  "org.hibernate:hibernate-core@4.3.7.Final";
var testIgnoreStrings: string[] = readFileSync(testPackagesFilename)
  .toString()
  .split("\n");

describe("match package ignore strings", function() {
  it("exact match with version", async () => {
    // console.log(testIgnoreStrings)
    expect(
      checkIgnoreListMatch(testIgnoreStrings, testVersionMatchFromDependency)
    ).toBeTruthy();
  });

  it("match without version", async () => {
    // console.log(testIgnoreStrings)
    expect(
      checkIgnoreListMatch(testIgnoreStrings, testPackageMatchFromDependency)
    ).toBeTruthy();
  });

  it("match wildcard", async () => {
    // console.log(testIgnoreStrings)
    expect(
      checkIgnoreListMatch(testIgnoreStrings, testWildcardMatchFromDependency)
    ).toBeTruthy();
  });
});
