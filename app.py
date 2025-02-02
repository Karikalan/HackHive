import os
from flask import Flask, render_template, request, send_from_directory
from encrypt_decrypt import encrypt_image, decrypt_image
from werkzeug.utils import secure_filename
import logging

# Setup logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        logging.debug("Encrypt form submitted")
        password = request.form['password']
        file = request.files['image']
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        with open(filepath, "rb") as f:
            image_data = f.read()
        
        encrypted_data = encrypt_image(image_data, password)
        encrypted_file = filename + ".txt"
        
        with open(os.path.join(app.config['UPLOAD_FOLDER'], encrypted_file), "wb") as f:
            f.write(encrypted_data)
        
        return render_template('encrypt_result.html', filename=filename, encrypted_file=encrypted_file)
    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        logging.debug("Decrypt form submitted")
        password = request.form['password']
        file = request.files['encrypted_file']
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        with open(filepath, "rb") as f:
            encrypted_data = f.read()
        
        try:
            decrypted_data = decrypt_image(encrypted_data, password)
            decrypted_file = filename.replace(".txt", "_decrypted.png")
            
            with open(os.path.join(app.config['UPLOAD_FOLDER'], decrypted_file), "wb") as f:
                f.write(decrypted_data)
            
            logging.debug("Decryption successful")
            return render_template('decrypt_result.html', filename=filename, decrypted_file=decrypted_file)
        except ValueError as e:
            logging.error(f"Decryption failed: {e}")
            return render_template('decrypt.html', error=str(e))
    return render_template('decrypt.html')

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    custom_name = request.args.get('name')
    file_extension = request.args.get('extension')
    if custom_name and file_extension:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True, download_name=custom_name + file_extension)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
