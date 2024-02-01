from rest_framework import serializers



class CredentialSerializer(serializers.Serializer):
    access_key = serializers.CharField(max_length=255)
    secret_access_key = serializers.CharField(max_length=255)
    region_name = serializers.CharField(max_length=255)
    

class ListObjectSerializer(serializers.Serializer):
    #i want the bucket_name should be no gaps or periods
    bucket_name = serializers.CharField(max_length=50)
    next_token = serializers.CharField(max_length=50, required=False)

    def validate_bucket_name(self, value):
        # Check if the bucket_name contains spaces or periods
        if ' ' in value or '.' in value:
            raise serializers.ValidationError("Bucket name should not contain spaces or periods. Make sure the bucket name is correct")
        return value


class UploadFileSerializer(serializers.Serializer):
    bucket_name = serializers.CharField(max_length=50)
    original_name = serializers.CharField(max_length=50)

    def validate_bucket_name(self, value):
        # Check if the bucket_name contains spaces or periods
        if ' ' in value or '.' in value:
            raise serializers.ValidationError("Bucket name should not contain spaces or periods. Make sure the bucket name is correct")
        return value
    
    
class RenameSerializer(serializers.Serializer):
    bucket_name = serializers.CharField(max_length=50)
    new_object_key = serializers.CharField(max_length=50)

    def validate_bucket_name(self, value):
        # Check if the bucket_name contains spaces or periods
        if ' ' in value or '.' in value:
            raise serializers.ValidationError("Bucket name should not contain spaces or periods. Make sure the bucket name is correct")
        return value
    