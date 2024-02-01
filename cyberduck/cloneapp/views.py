import uuid
import boto3
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import KeysModel
from .serializers import *
from botocore.exceptions import ClientError, NoCredentialsError
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
import jwt
from rest_framework import status
from datetime import datetime, timedelta, timezone
from rest_framework.decorators import api_view




my_secret_key = 'd8c5dab4-a6be-11ee-b201-9db6b614fddb'





#initializing s3 client for once
def s3_client_initializing(access_key,secret_access_key,region_name):

    return boto3.client(
        's3',aws_access_key_id = access_key,aws_secret_access_key = secret_access_key,region_name=region_name)
    
    
def create_presigned_url(client_method, object_key, bucket_name,access_key,secret_access_key,region_name,expiration=3600):
    
    s3_client = s3_client_initializing(access_key,secret_access_key,region_name)
    response = s3_client.generate_presigned_url(
        ClientMethod = client_method,
        Params = {
            'Bucket': bucket_name,
            'Key': object_key
        },
        ExpiresIn = expiration
    )
    return response
    




class CyberDuckClass():
    

    @api_view(['POST'])
    def authenticate(request):
        try:
            serializer = CredentialSerializer(data=request.data)
            if serializer.is_valid():
                #need to check credentials are correct or not
                access_key = serializer.validated_data['access_key']
                secret_access_key = serializer.validated_data['secret_access_key']
                region_name = serializer.validated_data['region_name']
              
                s3 = s3_client_initializing(access_key,secret_access_key,region_name)

                #need to check weather the s3 client is valid or not
                #below is just a test to check the credentials are correct or not
                #list all the objects in a bucket
                # bucket_name = 'practice-demo-testing'
                # obj_list = []
                # response= s3.list_objects_v2(Bucket=bucket_name)
                # for obj in response['Contents']:
                #     obj_list.append(obj['Key'])



                #list of bukcets
                # bucket_list = []
                response = s3.list_buckets()
                # for bucket in response['Buckets']:
                #     bucket_list.append(bucket)
                # bucket_list = [bucket for bucket in response['Buckets']]
                # length_of_buckets = len(bucket_list)




                # Create a JWT token with AWS credentials
                expiration_time = datetime.now() + timedelta(days=1)
                expiration_timestamp = int(expiration_time.timestamp())

                #payload, this contains user details generally but for this aws credentials
                token_data = {
                    'access_key': access_key,
                    'secret_access_key': secret_access_key,
                    'region_name': region_name,
                    'exp': expiration_timestamp
                }
                jwt_token = jwt.encode(token_data, my_secret_key, algorithm='HS256')

                return Response({'success': True , 'message': 'User succesfully login and credentials are correct','jwt_token': jwt_token})
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except ClientError as e:
            return Response({'client_error': str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



    #get method
    @api_view(['GET'])
    def listBuckets(request):
        try:
            # Extract JWT token from the Authorization header
            jwt_token = request.headers.get('Authorization')

            # Decode JWT token
            decoded_token = jwt.decode(jwt_token, my_secret_key, algorithms=['HS256'])

            # Retrieve AWS credentials from the decoded token
            access_key = decoded_token['access_key']
            secret_access_key = decoded_token['secret_access_key']
            region_name = decoded_token['region_name']
            
            s3 = s3_client_initializing(access_key,secret_access_key,region_name)

            #list of bukcets
            # bucket_list = []
            response = s3.list_buckets()
            # for bucket in response['Buckets']:
            #     bucket_list.append(bucket)
            bucket_list = [bucket for bucket in response['Buckets']]
            length_of_buckets = len(bucket_list)

            return Response({'success': True ,'length_of_buckets': length_of_buckets, 'bucket_list': bucket_list},status=status.HTTP_200_OK)
        
        except jwt.ExpiredSignatureError:
            return Response({'ExpiredSignatureError': 'JWT token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({'InvalidTokenError': 'Invalid JWT token'}, status=status.HTTP_401_UNAUTHORIZED)
        except ClientError as e:
            return Response({'client error': str(e)},status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'error': str(e)},status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    #list
    #getall
    @api_view(['GET'])
    def listObjects(request):
        try:
            jwt_token = request.headers.get('Authorization')
            decoded_token = jwt.decode(jwt_token, my_secret_key, algorithms=['HS256'])

            # Retrieve AWS credentials from the decoded token
            access_key = decoded_token['access_key']
            secret_access_key = decoded_token['secret_access_key']
            region_name = decoded_token['region_name']

            s3 = s3_client_initializing(access_key,secret_access_key,region_name)

            serializer = ListObjectSerializer(data=request.data)
            if serializer.is_valid():
                bucket_name = serializer.validated_data.get('bucket_name')
                next_token = serializer.validated_data.get('next_token')

                prefix = request.query_params.get('prefix', '') #search filter
                delimiter = request.query_params.get('delimiter', '')#folders (/)


                # List all the objects in a bucket
                #need to write pagination and list more than 1000
                if next_token:
                    response = s3.list_objects_v2(Bucket=bucket_name,Prefix = prefix,Delimiter=delimiter, ContinuationToken=next_token)
                else:
                    response = s3.list_objects_v2(Bucket=bucket_name,Prefix=prefix, Delimiter=delimiter, Sort='descending', SortKey='LastModified')
                    
                next_token = response.get('NextContinuationToken')

                obj_list = []
                for obj in response.get('Contents', []):
                    obj_list.append(obj['Key'])

                prefix_list = []
                # return common prefixes (subdirectories)
                for common_prefix in response.get('CommonPrefixes', []):
                    prefix_list.append(common_prefix['Prefix'])
                    
                final_list = prefix_list + obj_list
                length_of_objects = len(final_list)
                return Response({'success': True,'next_token': next_token,'length_of_objects': length_of_objects, 'objects': final_list},status=200)
            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        except jwt.ExpiredSignatureError:
            return Response({'expired_signature_error': 'JWT token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({'invalid_token_error': 'Invalid JWT token'}, status=status.HTTP_401_UNAUTHORIZED)
        except ClientError as e:
            return Response({"client_error": str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



    #create
    #upload
    #It generats a presigned url to upload a file to s3
    @api_view(['POST'])
    def uploadFilePresignedUrl(request):
        try:
            jwt_token = request.headers.get('Authorization')
            decoded_token = jwt.decode(jwt_token, my_secret_key, algorithms=['HS256'])

            access_key = decoded_token['access_key']
            secret_access_key = decoded_token['secret_access_key']
            region_name = decoded_token['region_name']

            serializer = UploadFileSerializer(data=request.data)
            if serializer.is_valid():
                bucket_name = serializer.validated_data.get('bucket_name')
                original_name = serializer.validated_data.get('original_name')

                #need to check if the bucket is in the list of buckets
            
                unique_code = str(uuid.uuid1())
                object_key = 'cyberduck/' + unique_code + original_name
                #upload a file
                response = create_presigned_url('put_object', object_key, bucket_name, access_key, secret_access_key, region_name)
                print('response = ', response, 'response')

                if response:
                    return Response({'SUCCESS': 'TRUE','presigned_url_to_upload': response, 'object_key':object_key}, status=status.HTTP_201_CREATED)
                else:
                    return Response({'SUCCESS': 'FALSE', 'error': 'Failed to generate presigned URL'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except jwt.ExpiredSignatureError:
            return Response({'Token Expired': 'JWT token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({'Invalid Token': 'Invalid JWT token'}, status=status.HTTP_401_UNAUTHORIZED)

        except ClientError as e:
            return Response({"ClientError": str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



    #retrive
    #download
    #It generates a presigned url to download a file
    @api_view(['GET'])
    def downloadFilePresignedUrl(request):
        try:
            jwt_token = request.headers.get('Authorization')
            decoded_token = jwt.decode(jwt_token, my_secret_key, algorithms=['HS256'])

            access_key = decoded_token['access_key']
            secret_access_key = decoded_token['secret_access_key']
            region_name = decoded_token['region_name']

            serializer = ListObjectSerializer(data=request.data)

            if serializer.is_valid():
                bucket_name = serializer.validated_data.get('bucket_name', '')
                object_key = serializer.validated_data.get('object_key', '')
            
                response = create_presigned_url('get_object',object_key,bucket_name,access_key,secret_access_key,region_name)

                if response:
                        return Response({'success' : True , 'presigned_url_to_download_a_file': response}, status=status.HTTP_200_OK)
                else:
                    return Response({'error': 'Failed to generate presigned URL'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        except jwt.ExpiredSignatureError:
            return Response({'error': 'JWT token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({'error': 'Invalid JWT token'}, status=status.HTTP_401_UNAUTHORIZED)

        except ClientError as e:
            return Response({"client_error": str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



    #update 
    #rename
    @api_view(['PUT'])
    def renameObject(request):
        try:
            jwt_token = request.headers.get('Authorization')
            decoded_token = jwt.decode(jwt_token, my_secret_key, algorithms=['HS256'])

            access_key = decoded_token['access_key']
            secret_access_key = decoded_token['secret_access_key']
            region_name = decoded_token['region_name']

            s3 = s3_client_initializing(access_key,secret_access_key,region_name)

            serializer = RenameSerializer(data=request.data)
            if serializer.is_valid():
                bucket_name = serializer.validated_data.get('bucket_name','')
                old_object_key = serializer.validated_data.get('old_object_key')
                new_object_key = serializer.validated_data.get('new_object_key')

                # Copy
                response = s3.copy_object(
                    Bucket=bucket_name,
                    Key=new_object_key,  #new key
                    CopySource={
                        'Bucket':bucket_name,
                        'Key': old_object_key  #old key
                        }
                )

                #deleting the old
                response = s3.delete_object(
                    Bucket = bucket_name,
                    Key = old_object_key
                )
                

                return Response({'success': True, 'message': 'Succesfully renamed the object key'})
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except jwt.ExpiredSignatureError:
            return Response({'expired_signature_error': 'JWT token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({'invalid_token_error': 'Invalid JWT token'}, status=status.HTTP_401_UNAUTHORIZED)
        except ClientError as e:
            return Response({"client_error": str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


    #destroy
    #delete
    @api_view(['DELETE'])
    def deleteObject(request):
        try:
            jwt_token = request.headers.get('Authorization')
            decoded_token = jwt.decode(jwt_token, my_secret_key, algorithms=['HS256'])

            access_key = decoded_token['access_key']
            secret_access_key = decoded_token['secret_access_key']
            region_name = decoded_token['region_name']

            serializer = ListObjectSerializer(data=request.data)
            if serializer.is_valid():
                bucket_name = serializer.validated_data.get('bucket_name', '')
                object_key = serializer.validated_data.get('object_key', '')

                s3 = s3_client_initializing(access_key,secret_access_key,region_name)
    
                response = s3.delete_object(
                    Bucket=bucket_name,
                    Key=object_key
                )

                if response['DeleteMarker'] == True:
                    return Response({'success' : False, 'message': 'Succesfully deleted the object'},status=status.HTTP_200_OK)
                else:
                    return Response({'error': 'Failed to delete the object'},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        except jwt.ExpiredSignatureError:
            return Response({'error': 'JWT token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({'error': 'Invalid JWT token'}, status=status.HTTP_401_UNAUTHORIZED)
        except ClientError as e:
            return Response({"ClientError": str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    
        
