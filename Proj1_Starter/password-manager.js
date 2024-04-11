"use strict";


/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor() {
    this.data = {
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
    };

    // throw "Not Implemented!";
  };

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    try {
      const salt =await subtle.digest("SHA-256", stringToBuffer(password)); 
      const KEY = await genKeyFromMasterPassword(password, salt);
      let keychain = new Keychain();

      // const r1 = getRandomBytes(32);
      // const hmacKeyDomain = await subtle.sign(
      //   {
      //     name: "HMAC",
      //   },
      //   KEY,
      //   r1,
      // );

      // const r2 = getRandomBytes(32);
      // const hmacKeyPassword = await subtle.sign(
      //   {
      //     name: "HMAC",
      //   },
      //   KEY,
      //   r2,
      // );

      keychain.secrets = {
        masterPassword: password,
        salt: salt,
        KEY: KEY,
        // hmacKeyDomain: hmacKeyDomain,
        // hmacKeyPassword: hmacKeyPassword
      };

      return keychain;
    } catch (error) {
      console.log("Error generating keychain:", error);
      throw error;
    }
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    try {
      const pmJson = repr;

      if (trustedDataCheck !== undefined) {
        const computedShaStr = await subtle.digest('sha-256', stringToBuffer(pmJson));
        console.log(computedShaStr);
        console.log(trustedDataCheck);
        if (!compareArrayBuffers(computedShaStr, trustedDataCheck)) {
          throw new Error('Integrity check failed. The checksum does not match');
        }
      } else {
        console.log("No checksum provided");
        return null;
      }

      let keychain = new Keychain();
      keychain.data = JSON.parse(pmJson);
      return keychain;

    } catch (error) {
      console.error("Error loading keychain:", error);
      throw error;
    }
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */
  async dump() {
    try {
      const pmJson = JSON.stringify(this.data);
      const pmShaStr = await subtle.digest('sha-256', stringToBuffer(pmJson));
      return [pmJson, pmShaStr];
    } catch (error) {
      console.error("Error dumping value:", error);
      throw error;
    }
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    try {
      const name_sign = await subtle.sign("HMAC", this.secrets.hmacKeyDomain, stringToBuffer(name));
      const base64NameSignature = btoa(String.fromCharCode.apply(null, new Uint8Array(name_sign)));
      if (this.data[base64NameSignature] !== undefined) {
        return this.data[base64NameSignature];
      }
      else {
        return null;
      }
    } catch (error) {
      console.error("Error getting value:", error);
      throw error;
    }
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    try {

      let existingEntry = await this.get(name);
      // console.log(existingEntry);
      if (existingEntry !== null) {
        console.log(`Updating entry for ${name}`);
      } else {
        console.log(`Adding new entry for ${name}`);
      }
      const name_sign = await subtle.sign("HMAC", this.secrets.hmacKeyDomain, stringToBuffer(name));
      const base64NameSignature = btoa(String.fromCharCode.apply(null, new Uint8Array(name_sign)));
      const value_encrypted = await subtle.encrypt("AES-GCM", this.secrets.hmacKeyPassword, stringToBuffer(value));
      this.data[base64NameSignature] = String(value_encrypted);
    } catch (error) {
      console.error("Error setting value:", error);
      throw error;
    }
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    try {
      const name_sign = await subtle.sign("HMAC", this.secrets.hmacKeyDomain, stringToBuffer(name));
      const base64NameSignature = btoa(String.fromCharCode.apply(null, new Uint8Array(name_sign)));
      if (this.data[base64NameSignature] !== undefined) {
        delete this.data[base64NameSignature];
        return true;
      }
      else {
        return false;
      }
    } catch (error) {
      console.error("Error removing value:", error);
      throw error;
    }
  };
};

module.exports = { Keychain }


function getKeyMaterial(password) {
  return subtle.importKey(
    "raw",
    Buffer.from(password),
    {
      name: "PBKDF2"
    },
    false, // Whether the key will be extractable 
    ["deriveKey"]
  );
}

async function genKeyFromMasterPassword(password, _salt) {
  try {
    const keyMaterial = await getKeyMaterial(password);
    const key = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: _salt,
        hash: "SHA-256",
        iterations: PBKDF2_ITERATIONS,
      },
      keyMaterial,
      {
        name: "HMAC",
        hash: "SHA-256",
        length: 128
      },
      false,
      ["sign"]
    );
    return key;

  } catch (error) {
    console.error("error:", error);
    throw error;
  }
}

function compareArrayBuffers(buf1, buf2) {
  // Create Uint8Array views for both ArrayBuffer objects
  const view1 = new Uint8Array(buf1);
  const view2 = new Uint8Array(buf2);

  // Compare the entire Uint8Array arrays at once
  return view1.length === view2.length && view1.every((value, index) => value === view2[index]);
}