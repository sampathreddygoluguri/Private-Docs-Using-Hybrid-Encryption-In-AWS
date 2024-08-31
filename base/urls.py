from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from .views import home, user_login, user_register, show_pub_key, upload_and_encrypt, list_of_encrypted_file, decrypt_file, user_logout, upload_and_encrypt_layer2, decrypt_file2, file_list3, upload_file_view, list_files_view, decrypt_files_view, download_private_key, download_decrypted_file
urlpatterns = [
    path('', home, name='home'),
    path('login/', user_login, name='login'),
    path('register/', user_register, name='register'),
    path('publickey/', show_pub_key, name='showpublickey'),
    path('encrypt/', upload_and_encrypt, name='encrypt'),
    path('list/', list_of_encrypted_file, name='fileList'),
    path('list/<filename>', decrypt_file, name='decrypt'),
    path('logout/', user_logout, name='userLogout'),
    path('encryptl3/', upload_and_encrypt_layer2, name='encryptl3'),
    path('list3/', file_list3, name='list3'),
    path('list3/<filename>', decrypt_file2, name='decryptl3'),

    path('upload/', upload_file_view, name='upload_file'),
    path('download/<str:key_filename>/', download_private_key, name='download_private_key'),
    path('files/', list_files_view, name='file_list'),
    path('decrypt/<str:filename>/', decrypt_files_view, name='decrypt_files'),
    path('download_decrypted_file/<str:filename>/', download_decrypted_file, name='download_decrypted_file')
    
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)