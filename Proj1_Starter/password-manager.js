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
      const salt = await subtle.digest(
        "SHA-256",
        stringToBuffer(password)
      );

      const KEY = await genKeyFromMasterPassword(password, salt);
      const keychain = new Keychain();
      keychain.data.salt = bufferToString(salt);
      keychain.secrets = {
        masterPassword: password,
        KEY: KEY
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

        if (bufferToString(computedShaStr) !== trustedDataCheck) {
          throw new Error('Integrity check failed. The checksum does not match');
        }
      } else {
        console.log("No checksum provided");
        return null;
      }

      const salt = await subtle.digest(
        'SHA-256',
        stringToBuffer(password)
      );

      console.log(pmJson);
      const jsonData = JSON.parse(pmJson);
      console.log(jsonData.salt);
      if (bufferToString(salt) !== jsonData.salt) {
        console.log(1);
        throw new Error('incorrect password');
      }
      console.log(2);
      let keychain = new Keychain();
      keychain.data = jsonData;

      const KEY = await genKeyFromMasterPassword(password, salt);
      keychain.secrets.masterPassword = password;
      keychain.secrets.KEY = KEY;


      console.log("keychain", keychain);
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

      const pmShaStr = await subtle.digest(
        'SHA-256',
        stringToBuffer(pmJson)
      );
      // console.log(this);
      
      return [pmJson, bufferToString(pmShaStr)];
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
  async get(Name) {
    try {

      /**----------------------- */
      const r1 = await subtle.digest(
        "SHA-256",
        stringToBuffer(Name)
      );

      const domain_key = await subtle.sign(
        {
          name: "HMAC",
        },
        this.secrets.KEY,
        r1
      );

      const domainName_key = await subtle.importKey(
        "raw",
        domain_key,
        {
          name: "HMAC",
          hash: "SHA-256"
        },
        false,
        ["sign"]
      );

      const name_sign = await subtle.sign(
        "HMAC",
        domainName_key,
        stringToBuffer(Name)
      );

      const Entry = btoa(String.fromCharCode.apply(null, new Uint8Array(name_sign)));

      /**----------------------------- */

      const name = Object.keys(this.data).find(key => key === Entry);

      // console.log(this.data);
      if (name === undefined) {

        return null;
      } else {
        console.log("Found value for", name);


        // get the corresponded encrypted password
        const encrypted_password = Buffer.from(this.data[Entry], 'base64');


        // decrypt the password
        // iv is the first 16 bytes of encrypted password
        const iv = encrypted_password.subarray(0, 16);

        const r2 = await subtle.digest(
          "SHA-256",
          stringToBuffer(r1)
        );
        const pass_key = await subtle.sign(
          "HMAC",
          this.secrets.KEY,
          r2
        );
        const password_key = await subtle.importKey(
          "raw",
          pass_key,
          "AES-GCM",
          false,
          ["decrypt"]
        );

        const password = await subtle.decrypt(
          {
            name: "AES-GCM",
            iv: iv
          },
          password_key,
          encrypted_password.subarray(16,)
        );

        return bufferToString(password);
      }
    } catch (error) {
      console.log("Error getting value:", error);
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
      console.log("Setting value for", name, "to", value);

      /**------------------ */

      /**---------------------------------- */

      const r1 = await subtle.digest(
        "SHA-256",
        stringToBuffer(name)
      );


      const domain_key = await subtle.sign(
        {
          name: "HMAC",
        },
        this.secrets.KEY,
        r1
      );

      const domainName_key = await subtle.importKey(
        "raw",
        domain_key,
        {
          name: "HMAC",
          hash: "SHA-256"
        },
        false,
        ["sign"]
      );


      const name_sign = await subtle.sign(
        "HMAC",
        domainName_key,
        stringToBuffer(name)
      );

      const Entry = btoa(String.fromCharCode.apply(null, new Uint8Array(name_sign)));


      /**------------------------------- */

      const r2 = await subtle.digest(
        "SHA-256",
        stringToBuffer(r1)
      );
      const pass_key = await subtle.sign(
        "HMAC",
        this.secrets.KEY,
        r2
      ); //pass_key is used to create password_key by importKey()

      // generate an IV with length 128 bits
      const iv = getRandomBytes(16);

      const password_key = await subtle.importKey(
        "raw",
        pass_key,
        {
          name: "AES-GCM",
        },
        false,
        ["encrypt"]
      );

      const value_encrypted = await subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        password_key,
        stringToBuffer(value)
      );

      // arraybuffer to string

      const a = new Uint8Array(value_encrypted);
      const string_value_encrypted = btoa(String.fromCharCode.apply(null, new Uint8Array(concatenateUint8Arrays(iv, new Uint8Array(value_encrypted)))));


      this.data[Entry] = string_value_encrypted;

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
      console.log("Removing value for", name);

      /**----------------------- */
      const r1 = await subtle.digest(
        "SHA-256",
        stringToBuffer(name)
      );

      const domain_key = await subtle.sign(
        {
          name: "HMAC",
        },
        this.secrets.KEY,
        r1
      );

      const domainName_key = await subtle.importKey(
        "raw",
        domain_key,
        {
          name: "HMAC",
          hash: "SHA-256"
        },
        false,
        ["sign"]
      );

      const name_sign = await subtle.sign(
        "HMAC",
        domainName_key,
        stringToBuffer(name)
      );

      const Entry = btoa(String.fromCharCode.apply(null, new Uint8Array(name_sign)));

      /**----------------------------- */

      if (this.data[Entry] === undefined) {
        return false;
      } else {
        delete this.data[Entry];
        return true;
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
    stringToBuffer(password),
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
        length: 256
      },
      true,
      ["sign"]
    );
    return key;

  } catch (error) {
    console.error("error:", error);
    throw error;
  }
}


function concatenateUint8Arrays(first, second) {
  // Create a new array that can hold the combined length of both input arrays
  const concatenatedArray = new Uint8Array(first.length + second.length);

  // Copy the contents of the first array into the new array
  concatenatedArray.set(first, 0);

  // Copy the contents of the second array into the new array, starting right after the end of the first
  concatenatedArray.set(second, first.length);

  return concatenatedArray;
}
