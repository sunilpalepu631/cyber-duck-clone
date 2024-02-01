from django.urls import path
from .views import *



# urlpatterns = [
#     path('generatetoken/', GenerateAWSToken.as_view(),name ='generating-token'),
#     path('listbuckets/', ListBuckets.as_view()),

#     path('listcreate/', ListCreate.as_view(), name='list-upload-files'),
#     path('retrieveupdatedestroy/<str:key>', RetrieveUpdateDestroy.as_view(), name='download-rename-delete'),
# ]


urlpatterns = [
    path('authenticate/', CyberDuckClass.authenticate, name='authentication'),
    path('list-buckets/', CyberDuckClass.listBuckets, name='list all buckets'),
    path('list-objects/', CyberDuckClass.listObjects, name='list all objects'),
    path('upload-file/', CyberDuckClass.uploadFilePresignedUrl, name='returns a presigned url to uplaod a file'),
    path('download-file/', CyberDuckClass.downloadFilePresignedUrl, name='presigned url to downlaod file'),
    path('rename-object/', CyberDuckClass.renameObject, name='renames the object'),
    path('delete-object/', CyberDuckClass.deleteObject, name='deletes an object in s3'),

]
