
"""
    Secure File Encryption and Decryption
    This script provides a GUI to encrypt and decrypt files using RSA and ChaCha20 algorithms.
    It includes key generation, file selection, and mechanisms for secure data handling and verification.

    This file includes:
    - Organized imports
    - Consistent naming conventions
    - Minimized global usage, kept at the start of the script
    - Modularised code
    - Extensive docstrings + comments
    - Error handling
    - Consistent indentation + spacing
    - GUI layout + functionality
    - Code documentation

    Author: Joshua Connolly 17084803
    Date: 19/01/2024
    """

# Standard libraries first, followed by third-party libraries, and then local application/library specific imports.
import base64
import os
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox, Label

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Global variables for keys and GUI labels
global user_rsa_public_key, user_rsa_private_key
global label_current_recipient, label_current_user
global sender_id_for_decryption

# Setting key vars to null
user_rsa_public_key = None
user_rsa_private_key = None

# Used for identifying the sender in digital signatures
sender_id = None
# Used for identifying the sender during decryption
sender_id_for_decryption = None


def generate_rsa_keys(user_id):
    """
        Generates RSA key pairs (both private and public keys) along with signing keys for a given user.

        This function creates two sets of RSA keys for each user - one for encryption/decryption and another pair
        for signing/verification purposes. The encryption RSA keys and the signing RSA keys are generated separately.
        Each key pair consists of a private key and a corresponding public key. The key size and public exponent
        are predefined.

        The generated keys are saved into separate .pem files for persistent storage and future use. The encryption
        private key is saved in a file named [user_id]_private_key.pem, and the corresponding public key is saved
        in [user_id]_public_key.pem. Similarly, the signing private key is saved in [user_id]_signing_private_key.pem,
        and the signing public key in [user_id]_signing_public_key.pem.

        Args:
        user_id (str): The identifier for the user for whom the keys are being generated.

        Returns:
        None: This function does not return a value but performs file I/O operations.
        """

    # Generating RSA key pairs
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Signing/verification keys
    signing_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    signing_public_key = signing_private_key.public_key()

    # Saving signing keys to .pem files
    signing_private_key_file = f'{user_id}_signing_private_key.pem'
    signing_public_key_file = f'{user_id}_signing_public_key.pem'

    with open(signing_private_key_file, 'wb') as f:
        f.write(signing_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(signing_public_key_file, 'wb') as f:
        f.write(signing_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # Saving RSA key pairs to .pem files
    private_key_file = f'{user_id}_private_key.pem'
    public_key_file = f'{user_id}_public_key.pem'

    with open(private_key_file, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(public_key_file, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


def get_user_id_and_generate_keys():
    """
        Prompts the user to enter identifiers for two different users and generates RSA keys for both.

        This function facilitates the initialization of RSA keys for encryption and decryption by first obtaining
        user identifiers through a GUI dialog. The user is asked to input identifiers for two separate users
        (User 1 and User 2). Upon receiving these identifiers, the function calls 'generate_rsa_keys' for each
        identifier to generate the corresponding RSA key pairs.

        The function ensures that keys are generated only if valid identifiers are provided for both users.
        If either identifier input is empty or canceled, the function will not proceed with key generation.

        Returns:
        None: This function does not return a value but calls another function to generate keys and performs GUI interactions.
        """
    user_id_1 = simpledialog.askstring("Input", "Enter identifier for User 1:")
    user_id_2 = simpledialog.askstring("Input", "Enter identifier for User 2:")

    if user_id_1 and user_id_2:
        generate_rsa_keys(user_id_1)
        generate_rsa_keys(user_id_2)

def select_file():
    """
        Opens a file dialog for the user to select a file intended for encryption or decryption.

        This function activates a file selection dialog box, allowing the user to navigate their file system and
        select a file. Once a file is chosen, its path is stored in a global variable 'file_path'. The function
        then updates the GUI to display the name of the selected file. This visual feedback ensures that the user
        is aware of the currently selected file which will be subject to subsequent encryption or decryption
        operations.

        If the user cancels the file selection or doesn't choose a file, the global variable 'file_path' remains
        unchanged, and no update is made to the GUI regarding the selected file.

        Global Variables:
        file_path (str): Path of the file selected by the user.
        label_selected_file (tk.Label): GUI element displaying the name of the selected file.

        Returns:
        None: This function does not return a value but updates global variables and the GUI.
        """
    global file_path
    file_path = filedialog.askopenfilename()
    if file_path:
        label_selected_file.config(text=f"Selected File: {os.path.basename(file_path)}")


def get_recipient_id():
    """
        Prompts the user to enter the identifier for the recipient of an encrypted message.

        This function opens a dialog box requesting the user to input an identifier for the intended recipient
        of an encrypted file. Once the recipient's identifier is provided, the function retrieves the corresponding
        RSA public key using the 'get_rsa_public_key' function. This public key is crucial for the encryption
        process, as it will be used to encrypt the symmetric key that secures the file's contents.

        The recipient's RSA public key is stored in a global variable for ease of access during the encryption process.
        Additionally, the GUI is updated to display the current recipient's identifier, providing visual confirmation
        of the recipient selection. If the user does not provide an identifier, the global variable is not updated,
        and the GUI reflects that no recipient is currently selected.

        Global Variables:
        user_rsa_public_key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey): The RSA public key of the recipient.
        label_current_recipient (tk.Label): GUI element displaying the identifier of the current recipient.

        Returns:
        None: This function does not return a value but updates global variables and the GUI.
        """
    global user_rsa_public_key, label_current_recipient
    recipient_id = simpledialog.askstring("Recipient", "Enter the identifier for the recipient:")
    if recipient_id:
        user_rsa_public_key = get_rsa_public_key(recipient_id)
        label_current_recipient.config(text=f"Current Recipient: {recipient_id}")
    else:
        label_current_recipient.config(text="Current Recipient: None")

# Function to retrieve the RSA public key for a given identifier
def get_rsa_public_key(user_id):
    """
        Retrieves the RSA public key for a given user identifier.

        Args:
        user_id (str): The identifier of the user whose public key is being retrieved.

        This function attempts to open and read the user's public key from a PEM file named [user_id]_public_key.pem.
        If successful, it returns the RSA public key; otherwise, it shows an error message and returns None.

        Returns:
        rsa.PublicKey: The RSA public key of the user, or None if the key could not be retrieved.
        """
    try:
        with open(f"{user_id}_public_key.pem", "rb") as key_file:
            return serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
    except IOError:
        messagebox.showerror("Error", f"Could not find RSA public key for user {user_id}")
        return None

def set_user_rsa_private_key():
    """
        Prompts the user to enter their identifier to set their RSA private key for decryption.

        This function opens a dialog box requesting the user to provide their unique identifier. Once the identifier
        is input, it uses the 'get_rsa_private_key' function to retrieve the corresponding RSA private key from a
        storage file. The retrieved private key is crucial for decrypting files that were encrypted using the user's
        public key.

        The RSA private key is then stored in a global variable for accessibility during the decryption process.
        Additionally, the function updates the GUI to display the current user's identifier and sets the 'sender_id'
        global variable to the user's identifier. If the user does not enter an identifier or cancels the input,
        the function resets the global variables and updates the GUI to indicate that no current user is set.

        Global Variables:
        user_rsa_private_key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey): The RSA private key of the user.
        label_current_user (tk.Label): GUI element displaying the identifier of the current user.
        sender_id (str): Identifier of the sender, set for use in the encryption process.

        Returns:
        None: This function does not return a value but updates global variables and the GUI.
        """
    global user_rsa_private_key, label_current_user, sender_id
    user_id = simpledialog.askstring("User ID", "Enter your identifier:")
    if user_id:
        user_rsa_private_key = get_rsa_private_key(user_id)
        label_current_user.config(text=f"Current User: {user_id}")
        sender_id = user_id  # Set the sender_id here
    else:
        label_current_user.config(text="Current User: None")
        sender_id = None  # Reset sender_id if no user ID is provided

def get_rsa_private_key(user_id):
    """
        Retrieves the RSA private key for a given user identifier.

        Args:
        user_id (str): The identifier of the user whose private key is being retrieved.

        This function attempts to open and read the user's private key from a PEM file named [user_id]_private_key.pem.
        The private key is expected to be unprotected (no passphrase). If the key retrieval is successful,
        it returns the RSA private key; otherwise, it displays an error and returns None.

        Returns:
        rsa.PrivateKey: The RSA private key of the user, or None if the key could not be retrieved.
        """
    try:
        with open(f"{user_id}_private_key.pem", "rb") as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # If your key is password protected, handle it here
                backend=default_backend()
            )
    except IOError:
        messagebox.showerror("Error", f"Could not find RSA private key for user {user_id}")
        return None


def get_rsa_signing_private_key(user_id):
    """
        Retrieves the RSA signing private key for a specified user based on their identifier.

        This function attempts to access and load the RSA signing private key of a user from a file. The file name
        is expected to follow the format '[user_id]_signing_private_key.pem'. The function uses the cryptography
        library to read and deserialize the private key from the PEM file.

        If the key is password-protected, additional handling can be implemented as needed. In case the file
        corresponding to the provided user identifier does not exist or cannot be opened, the function will display
        an error message to the user and return None.

        Args:
        user_id (str): The identifier of the user whose signing private key is being retrieved.

        Returns:
        rsa.PrivateKey: The RSA signing private key of the user if successfully retrieved, or None if the key
        could not be retrieved or the file does not exist.

        Exceptions:
        IOError: An error occurred while trying to read the file.
        """
    try:
        with open(f"{user_id}_signing_private_key.pem", "rb") as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # If the key is password protected, handle it here
                backend=default_backend()
            )
    except IOError:
        messagebox.showerror("Error", f"Could not find RSA signing private key for user {user_id}")
        return None

def get_rsa_signing_public_key(user_id):
    """
        Retrieves the RSA signing public key for a specific user based on their identifier.

        This function is designed to access and load a user's RSA signing public key from a file. The expected
        file naming convention is '[user_id]_signing_public_key.pem', where the user_id is used to locate the
        appropriate file. The function utilizes the cryptography library to read the public key from the PEM file
        and deserialize it into an RSA public key object.

        If the file associated with the provided user identifier does not exist or an error occurs during file
        reading, an error message is displayed to the user, and the function returns None.

        Args:
        user_id (str): The identifier of the user whose signing public key is being retrieved.

        Returns:
        rsa.PublicKey: The RSA signing public key of the user if successfully retrieved, or None if the key
        could not be found or the file cannot be opened.

        Exceptions:
        IOError: An error occurred while trying to read the file.
        """
    try:
        with open(f"{user_id}_signing_public_key.pem", "rb") as key_file:
            return serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
    except IOError:
        messagebox.showerror("Error", f"Could not find RSA signing public key for user {user_id}")
        return None

def set_sender_id_for_decryption():
    """
        Prompts the user to enter the identifier of the sender for decryption purposes.

        This function opens a simple dialog box asking the user to input the identifier of the sender
        whose encrypted file is to be decrypted. The entered identifier is stored in a global variable
        'sender_id_for_decryption', which is used to retrieve the appropriate RSA signing public key
        during the decryption process.
        """
    global sender_id_for_decryption
    sender_id_for_decryption = simpledialog.askstring("Sender ID", "Enter sender's identifier for decryption:")

def encrypt_file(rsa_public_key, sender_id):
    """
        Encrypts the selected file using ChaCha20 encryption and RSA-encrypted symmetric key.

        This function handles the encryption of a user-selected file. It first checks if a file has been selected
        and if the recipient's RSA public key is available. A symmetric key for ChaCha20 encryption is generated
        and encrypted with the recipient's RSA public key. The function then reads the data from the selected file,
        creates an HMAC for integrity verification, and signs this HMAC with the sender's RSA signing private key.
        The data is encrypted using the ChaCha20 algorithm with the generated symmetric key.

        The encrypted data is saved in a new file with an '.encrypted' extension. Additionally, the nonce,
        encrypted symmetric key, HMAC, and signature are stored in a separate .pem file. This .pem file is used
        during decryption to verify the integrity and authenticity of the encrypted data.

        Args:
        rsa_public_key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey): The RSA public key of the recipient.
        sender_id (str): The identifier of the sender whose private key is used for signing the HMAC.

        Returns:
        None: This function does not return a value but performs file I/O and user interface operations.
        """
    global user_rsa_public_key
    if not file_path or not user_rsa_public_key:
        messagebox.showerror("Error", "No file selected for encryption or recipient RSA key missing")
        return

    # Generate a random symmetric key for ChaCha20
    symmetric_key = os.urandom(32)

    # Encrypt the symmetric key using the recipient's RSA public key
    encrypted_symmetric_key = user_rsa_public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    try:
        with open(file_path, 'rb') as file:
            data = file.read()

        # Creating HMAC for integrity check
        h = hmac.HMAC(symmetric_key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        hmac_value = h.finalize()

        # Sign the HMAC
        sender_signing_private_key = get_rsa_signing_private_key(sender_id)
        signature = sender_signing_private_key.sign(
            hmac_value,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Encrypting the data
        chacha = ChaCha20Poly1305(symmetric_key)
        nonce = os.urandom(12)
        encrypted_data = chacha.encrypt(nonce, data, None)

        # Writing the encrypted data, HMAC, and encrypted symmetric key to files
        encrypted_file_path = file_path + '.encrypted'
        with open(encrypted_file_path, 'wb') as file:
            file.write(encrypted_data)

        pem_file_path = file_path + '.pem'
        with open(pem_file_path, 'w') as file:
            file.write(f"-----BEGIN CHACHA20 DATA-----\\n")
            file.write(f"Nonce: {base64.b64encode(nonce).decode()}\\n")
            file.write(f"Symmetric Key: {base64.b64encode(encrypted_symmetric_key).decode()}\\n")
            file.write(f"HMAC: {base64.b64encode(hmac_value).decode()}\\n")
            file.write(f"Signature: {base64.b64encode(signature).decode()}\\n")
            file.write(f"-----END CHACHA20 DATA-----")

        messagebox.showinfo("Success", "File encrypted successfully")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")


def decrypt_file(sender_id):
    """
        Decrypts an encrypted file using the ChaCha20 algorithm and RSA-decrypted symmetric key.

        This function performs decryption of a file that was previously encrypted using the encrypt_file function.
        It first checks if an encrypted file is selected and if the RSA private key of the user is available.
        It then reads the associated PEM file to extract the nonce, encrypted symmetric key, stored HMAC, and signature.
        The symmetric key is decrypted using the user's RSA private key. The function then decrypts the file data
        with ChaCha20Poly1305 using the decrypted symmetric key. It verifies the integrity of the decrypted data
        by checking the HMAC and the authenticity of the signature using the sender's RSA signing public key.

        If both integrity and signature verifications pass, it saves the decrypted data into a new file with a '.decrypted'
        extension and notifies the user of successful decryption and verification. If the integrity check or signature
        verification fails, the user is warned accordingly.

        Args:
        sender_id (str): The identifier of the sender whose public key is used for signature verification.

        Returns:
        None: This function does not return a value but performs file I/O and user interface operations.
        """
    global user_rsa_private_key
    if not file_path or not file_path.endswith('.encrypted') or not user_rsa_private_key:
        messagebox.showerror("Error", "No encrypted file selected for decryption or RSA key missing")
        return

    # Define signature_verified here
    signature_verified = False

    try:
        pem_file_path = file_path[:-10] + '.pem'
        with open(pem_file_path, 'r') as file:
            pem_data = file.read()

        nonce = base64.b64decode(pem_data.split("\\n")[1].split(": ")[1])
        encrypted_symmetric_key = base64.b64decode(pem_data.split("\\n")[2].split(": ")[1])
        stored_hmac = base64.b64decode(pem_data.split("\\n")[3].split(": ")[1])
        signature = base64.b64decode(pem_data.split("\\n")[4].split(": ")[1])

        symmetric_key = user_rsa_private_key.decrypt(
            encrypted_symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        messagebox.showerror("Error", f"Could not read PEM file or decrypt symmetric key: {e}")
        return

    try:
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()

        chacha = ChaCha20Poly1305(symmetric_key)
        decrypted_data = chacha.decrypt(nonce, encrypted_data, None)

        h = hmac.HMAC(symmetric_key, hashes.SHA256(), backend=default_backend())
        h.update(decrypted_data)
        integrity_check_passed = False
        try:
            h.verify(stored_hmac)
            integrity_check_passed = True
        except Exception:
            integrity_check_passed = False

        sender_signing_public_key = get_rsa_signing_public_key(sender_id)
        try:
            sender_signing_public_key.verify(
                signature,
                stored_hmac,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            signature_verified = True
        except InvalidSignature:
            signature_verified = False

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during decryption: {e}")

    if integrity_check_passed and signature_verified:
        decrypted_file_path = file_path[:-10] + '.decrypted'
        with open(decrypted_file_path, 'wb') as file:
            file.write(decrypted_data)
        messagebox.showinfo("Success", "File decrypted and integrity verified successfully")
    else:
        messagebox.showwarning("Warning", "File decrypted but integrity check or signature verification failed")



# Setting up the GUI
root = tk.Tk()
root.title("Secure File Encryption/Decryption")

# Main instruction label for RSA Key Generation
label_instruction_rsa = Label(root, text="Generate RSA keys for two users.")
label_instruction_rsa.pack(pady=(10, 0))

# Frame for RSA Key Generation
frame_key_gen = tk.Frame(root, pady=5)
frame_key_gen.pack(fill=tk.X)

generate_keys_button = tk.Button(frame_key_gen, text="Generate RSA Keys", command=get_user_id_and_generate_keys)
generate_keys_button.pack(side=tk.LEFT, padx=5, expand=True)

# Main instruction label for Setting Keys
label_instruction_keys = Label(root, text="Set the Recipient & User keys.")
label_instruction_keys.pack(pady=(10, 0))

# Frame for Setting Keys
frame_set_keys = tk.Frame(root, pady=5)
frame_set_keys.pack(fill=tk.X)

get_recipient_id_button = tk.Button(frame_set_keys, text="Set Recipient Key", command=get_recipient_id)
get_recipient_id_button.pack(side=tk.LEFT, padx=5, expand=True)

set_user_key_button = tk.Button(frame_set_keys, text="Set User Key", command=set_user_rsa_private_key)
set_user_key_button.pack(side=tk.LEFT, padx=5, expand=True)

# Create labels for the current recipient and user
label_current_recipient = Label(root, text="Current Recipient: None")
label_current_user = Label(root, text="Current User: None")

label_current_recipient.pack(pady=(5, 0))
label_current_user.pack(pady=(5, 0))

# Main instruction label for File Selection
label_instruction_file = Label(root, text="Select a file.")
label_instruction_file.pack(pady=(10, 0))

# Frame for File Selection
frame_file_selection = tk.Frame(root, pady=5)
frame_file_selection.pack(fill=tk.X)

select_button = tk.Button(frame_file_selection, text="Select File", command=select_file)
select_button.pack(side=tk.LEFT, padx=20)

set_sender_id_button = tk.Button(frame_file_selection, text="Set Sender ID", command=set_sender_id_for_decryption)
set_sender_id_button.pack(side=tk.LEFT, padx=5)

# Label to display selected file
label_selected_file = Label(root, text="No file selected")
label_selected_file.pack(pady=(5, 0))

# Frame for Encryption/Decryption Operations
frame_operations = tk.Frame(root, pady=5)
frame_operations.pack(fill=tk.X)

encrypt_button = tk.Button(frame_operations, text="Encrypt", fg="blue", command=lambda: encrypt_file(user_rsa_public_key, sender_id) if sender_id else messagebox.showwarning("Warning", "Sender ID not set"))
encrypt_button.pack(side=tk.BOTTOM, padx=5)

decrypt_button = tk.Button(frame_operations, text="Decrypt", fg="red", command=lambda: decrypt_file(sender_id_for_decryption) if sender_id_for_decryption else messagebox.showwarning("Warning", "Sender ID not set for decryption"))
decrypt_button.pack(side=tk.BOTTOM, padx=5)

root.mainloop()

