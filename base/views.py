from django.shortcuts import render, redirect
from django.http import HttpResponse
from .forms import UserCreationForm
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import account, file_handler, file_handler_two, file_handler_three
import uuid
import os
import boto3
from django.contrib.auth import login, authenticate, logout
from algorithm.encryptor import encrypt, encryptl2
from algorithm.decryptor import decryptl1, decryptl2
from algorithm.encryptor3layer import encrypt3l1, encrypt3l2, encrypt3l3
from algorithm.decryptor3layer import decrypt3l1, decrypt3l2, decrypt3l3

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.http import HttpResponse, JsonResponse
from django.core.files.storage import FileSystemStorage
from django.core.files.base import ContentFile
from cryptography.hazmat.primitives import serialization
from algorithm.ecc_encryption import encrypt_ECC, decrypt_ECC, generate_key_pair, get_public_key_bytes
from django.http import FileResponse, Http404
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import ec as cryptography_ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from tinyec import registry, ec
import os, secrets, binascii, hashlib

curve = registry.get_curve('brainpoolP256r1')


# Create your views here.

access_key = "EXAMPLEACCESSKEY"
secret_access_key = "EXAMPLESECRETACCESSKEY"
bucket_name = "examplebucketname"

s3 = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_access_key)
def upload_to(filename):
    s3.put_object(Bucket=bucket_name, Key=(f's3/{filename}'+'/'))
    for subdir, dirs, files in os.walk('files/'+filename):
        for file in files:
            full_path = os.path.join(subdir, file)
            key = os.path.relpath(full_path, 'files/'+filename)
            s3.upload_file(full_path, bucket_name, key)
# Create your views here.

def home(request):
    return render(request, 'home.html')

#For Fernet and RSA
def upload_and_encrypt(request):
    context = {}
    if request.user.is_authenticated:
        if request.method == 'POST':
            filename = request.POST.get('filename')
            filename = filename + '.bin'
            file = request.FILES["file"]
            user = request.user
            user = account.objects.get(user=user)

            normalFile = file.read()
            with open(f'media/non_enc_file/{filename}', 'wb') as f:
                f.write(normalFile)
            FILE_PATH = 'media/non_enc_file/'+filename
            print(FILE_PATH)
            key1 = encrypt(FILE_PATH)
            key2, encrypted_file_path = encryptl2(FILE_PATH, filename)
            context['key1'] = key1
            context['key2'] = key2
            context['filename'] = filename
            file_dets = file_handler(user=user,filename=filename, fernetkeyl1=key1, fernetkeyl2=key2, encrypted_file_path=encrypted_file_path)
            file_dets.save()
        return render(request, 'encryption_page.html', context)
    return HttpResponse("<h1>You are not authenticated please go back</h1>")

#2FERNER and RSA
def upload_and_encrypt_layer2(request):
    context = {}
    if request.user.is_authenticated:
        if request.method == 'POST':
            filename = request.POST.get('filename')
            file = request.FILES["file"]
            user = request.user
            user = account.objects.get(user=user)

            normalfile = file.read()
            with open(f'media/non_enc_file/{filename}', 'wb') as f:
                f.write(normalfile)
            FILE_PATH = 'media/non_enc_file/' + filename

            key1 = encrypt3l1(FILE_PATH)
            key2 = encrypt3l2(FILE_PATH, filename)
            keyl3, encrypted_file_path = encrypt3l3(FILE_PATH, filename)
            
            context['key1'] = key1
            try:
                upload_to(filename)
                print("Upload Successful")
            except:
                print("Not successful")
                pass

            file_dets = file_handler_three(user=user, filename=filename, fernetkeyl1 = key1, fernetkeyl2=key2, fernetkeyl3 = keyl3,encrypted_file_path = encrypted_file_path)
            file_dets.save()
            context['filename'] = filename
        return render(request, 'encryption_page_layer3.html', context)
    return HttpResponse("<h4> Sorry you are not authenticated!!! </h4>")

def list_of_encrypted_file(request):
    context = {}
    if request.user.is_authenticated:
        user = request.user
        user = account.objects.get(user=user)
        all_file_dets = file_handler.objects.filter(user = user)
        context['all_files'] = all_file_dets
        return render(request, 'list_files.html', context)
    return HttpResponse('<h1> You are not authenticated cant fetch any list for you, Please go back to previous page.</h1>')

def file_list3(request):
    context = {}
    if request.user.is_authenticated:
        user = request.user
        user = account.objects.get(user=user)
        all_file_dets = file_handler_three.objects.filter(user = user)
        context['all_files'] = all_file_dets
        return render(request, 'list_files3.html', context)
    return HttpResponse('<h1> You are not authenticated cant fetch any list for you, Please go back to previous page.</h1>')


def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password = password)
        if user is not None:
            login(request, user)
        return redirect('/')

    return render(request, 'user_login.html')

def user_register(request):
    context = {}
    form = UserCreationForm()
    context['form'] = form
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            public_key = uuid.uuid4()
            new_user = account(user=user, public_key=public_key)
            new_user.save()
            login(request, user)
            return redirect('/')
    
    return render(request, 'user_register.html', context)

def show_pub_key(request):
    context = {}
    if request.user.is_authenticated:
        user = request.user
        find_user = account.objects.get(user=user)
        find_pub_key = find_user.public_key
        context['public_key'] = find_pub_key
        return render(request, 'show_pubkey.html', context)
    return render(request, 'show_pubkey.html', context)

def decrypt_file(request, filename):
    file_dets = file_handler.objects.get(filename=filename)
    context = {}
    if request.method == 'POST':
        key1 = request.FILES['keyl1']
        key2 = request.FILES['keyl2']
        file_path = file_dets.encrypted_file_path
        filename = file_dets.filename
        print(filename)
        decryptl1(file_path, filename)
        decryptl2(filename, key2)
        context['file_path'] = '/' + f'media/non_enc_file/{filename}'

        return render(request, 'decrypt_file.html', context)
    return render(request, 'decrypt_file.html', context)

def decrypt_file2(request, filename):
    file_dets = file_handler_three.objects.get(filename=filename)
    context = {}
    if request.method == 'POST':
        key1 = request.FILES['keyl1']
        key2 = request.FILES['keyl2']
        key3 = request.FILES['keyl3']
        file_path = file_dets.encrypted_file_path
        filename = file_dets.filename
        decrypt3l1(file_path, filename)
        decrypt3l2(filename, key2)
        decrypt3l3(filename, key3)
        context['file_path'] = '/' + f'media/non_enc_file/{filename}'

        return render(request, 'decrypt_file_three.html', context)
    return render(request, 'decrypt_file_three.html', context)
        

def user_logout(request):
    logout(request)
    return redirect('/')

@login_required
def upload_file_view(request):
    context = {}
    if request.method == 'POST' and request.FILES['file']:
        uploaded_file = request.FILES['file']
        filename = uploaded_file.name
        user = request.user

        # Save the uploaded file
        fs = FileSystemStorage(location='media/non_enc_file/')
        filename = fs.save(filename, uploaded_file)
        file_path = fs.path(filename)

        with open(file_path, 'rb') as f:
            file_data = f.read()

        # Encrypt the file data
        private_key = generate_key_pair()
        public_key = private_key.public_key()
        encrypted_data = encrypt_ECC(file_data, public_key)
        encrypted_filename = f"encrypted_{filename}"

        # Save the encrypted file
        encrypted_fs = FileSystemStorage(location='media/encrypted_files/')
        encrypted_file_path = encrypted_fs.path(encrypted_filename)
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data[0])

        # Save encryption details
        encryption_details = {
            'filename': encrypted_filename,
            'iv': binascii.hexlify(encrypted_data[1]).decode(),
            'tag': binascii.hexlify(encrypted_data[2]).decode(),
            'public_key': binascii.hexlify(encrypted_data[3]).decode()
        }

        details_filename = f"{filename}_details.txt"
        with open(fs.path(details_filename), 'w') as f:
            f.write(str(encryption_details))

        # Save the private key
        private_key_file = f"{filename}_private_key.pem"
        privKey_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_content = ContentFile(privKey_pem)
        key_fs = FileSystemStorage(location='media/key/')
        key_fs.save(private_key_file, private_key_content)

        # Upload the encrypted file (analogous to upload_to in the original function)
        try:
            upload_to(encrypted_filename)  # Assuming you have this function defined similarly
            print("Upload Successful")
        except:
            print("Not successful")
            pass

        # Save file details to the database
        file_dets = file_handler_two(user=user, filename=filename, encrypted_file_path=encrypted_file_path)
        file_dets.save()

        # Prepare response data
        context['message'] = 'File encrypted successfully.'
        context['private_key_file'] = private_key_file
        context['filename'] = filename

        return render(request, 'upload.html', context)

    return render(request, 'upload.html', context)



@login_required
def list_files_view(request):
    user = request.user
    user_files = file_handler_two.objects.filter(user=user)
    context = {'all_files': user_files}
    return render(request, 'file_list.html', context)

def download_private_key(request, key_filename):
    # Specify the location where private keys are stored
    key_fs = FileSystemStorage(location='media/key/')
    file_path = key_fs.path(key_filename)

    if not key_fs.exists(key_filename):
        raise Http404("Private key file does not exist.")

    # Return the file as an attachment for download
    response = FileResponse(open(file_path, 'rb'), as_attachment=True, filename=key_filename)
    return response

import logging
from django.urls import reverse
from urllib.parse import quote, unquote

logger = logging.getLogger(__name__)

@login_required
def decrypt_files_view(request, filename):
    context = {}

    # Remove potential prefix or username from the filename if needed
    base_filename = filename.split(' - ', 1)[-1]  # Adjust this if filename parsing is different

    try:
        # Retrieve file details from the database
        file_dets = file_handler_two.objects.get(filename=base_filename)
    except file_handler_two.DoesNotExist:
        logger.error(f"File details not found for filename: {base_filename}")
        raise Http404("File details not found.")

    if request.method == 'POST' and 'private_key_file' in request.FILES:
        private_key_file = request.FILES['private_key_file']

        # Load the private key from PEM format
        try:
            privKey_pem = private_key_file.read()
            private_key = serialization.load_pem_private_key(
                privKey_pem,
                password=None,
                backend=default_backend()
            )
        except Exception as e:
            logger.error(f"Failed to load private key: {e}")
            context['error'] = f"Failed to load private key: {e}"
            return render(request, 'decrypt.html', context)

        fs = FileSystemStorage(location='media/encrypted_files/')
        details_fs = FileSystemStorage(location='media/non_enc_file/')

        details_filename = f"{base_filename}_details.txt"
        encrypted_file_path = file_dets.encrypted_file_path

        # Debugging: log file paths
        logger.info(f"Attempting to open details file: {details_fs.path(details_filename)}")
        logger.info(f"Attempting to open encrypted file: {fs.path(encrypted_file_path)}")

        try:
            with open(details_fs.path(details_filename), 'r') as f:
                encryption_details = eval(f.read())
        except FileNotFoundError:
            logger.error(f"Details file does not exist: {details_fs.path(details_filename)}")
            raise Http404("Details file does not exist.")

        try:
            with open(fs.path(encrypted_file_path), 'rb') as f:
                encrypted_data = f.read()
        except FileNotFoundError:
            logger.error(f"Encrypted file does not exist: {fs.path(encrypted_file_path)}")
            raise Http404("Encrypted file does not exist.")

        # Extract encryption details
        iv = binascii.unhexlify(encryption_details['iv'])
        tag = binascii.unhexlify(encryption_details['tag'])
        public_key_bytes = binascii.unhexlify(encryption_details['public_key'])

        encrypted_file = (encrypted_data, iv, tag, public_key_bytes)

        # Decrypt the file
        try:
            decrypted_data = decrypt_ECC(encrypted_file, private_key)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            context['error'] = f"Decryption failed: {e}"
            return render(request, 'decrypt.html', context)

        decrypted_filename = f"decrypted_{base_filename}"

        # Save the decrypted file
        decrypted_fs = FileSystemStorage(location='media/decrypted_files/')
        decrypted_file_path = decrypted_fs.save(decrypted_filename, ContentFile(decrypted_data))

        # Generate URL for downloading the decrypted file
        decrypted_file_url = reverse('download_decrypted_file', args=[quote(decrypted_filename)])

        context.update({
            'filename': base_filename,
            'decrypted_file_url': decrypted_file_url,
            'decrypted_file_filename': decrypted_filename
        })

        return render(request, 'decrypt.html', context)

    return render(request, 'decrypt.html', context)


from django.utils.encoding import iri_to_uri

@login_required
def download_decrypted_file(request, filename):
    filename = unquote(filename)  # Decode the URL-encoded filename
    decrypted_fs = FileSystemStorage(location='media/decrypted_files/')
    file_path = decrypted_fs.path(filename)

    if not decrypted_fs.exists(filename):
        raise Http404("Decrypted file does not exist.")

    # Return the file as an attachment for download
    response = FileResponse(open(file_path, 'rb'), as_attachment=True, filename=filename)
    return response
