README.md

**Secure File Encryption and Decryption**

This Python script provides a graphical user interface (GUI) for encrypting and decrypting files using RSA and ChaCha20 algorithms. It's designed to facilitate secure file handling with strong encryption standards.

**Features**

• RSA Key Generation: Generates RSA key pairs for encryption/decryption and signing/verification.

• File Selection: Enables the user to select files for encryption or decryption.

• Secure Encryption and Decryption: Uses ChaCha20 for file encryption along with RSA-encrypted symmetric keys.

• Integrity and Authenticity Verification: Implements HMAC and digital signatures for verifying the integrity and authenticity of the encrypted/decrypted files.

• User-Friendly GUI: Provides an easy-to-use interface for all operations.

**Usage**

1. Generate RSA Keys: Click on 'Generate RSA Keys' to create key pairs for users.
2. Set Recipient and User Keys: Set the recipient's public key for encryption and the user's private key for decryption.
3. Select desired file for encryption/decryption.
4. File Operations:
     For Encryption: Select a file and click 'Encrypt'.
     For Decryption: Select an encrypted file and click 'Decrypt'.

_Note : Ensure all variables are set so that the program can read the respective key files saved._

**Installation**

    Clone the repository.
    Ensure Python 3.x is installed on your system.
    Install required dependencies: cryptography and tkinter.

**Dependencies**

    Python 3.x
    cryptography library
    tkinter for the GUI

**Contributing**

Feel free to fork the repository and submit pull requests.

**Author**

Joshua Connolly - 17084803
Manchester Metropolitan University
License

This project is licensed under the MIT License - see the LICENSE file for details.

**Acknowledgments**

    This script was created as a part of a secure file handling project.
    Special thanks to the Python and cryptography community for their invaluable resources.

_Note: This script is intended for educational purposes and should not be used as a replacement for professional encryption solutions in critical systems._

**Contact**

For any queries or suggestions, please contact Joshua Connolly at joshua.connolly2@stu.mmum.ac.com.
Version

_1.0 - Dated: 19/01/2024_
