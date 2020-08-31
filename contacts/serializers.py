from rest_framework import serializers
from .models import Contact


class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        # fields = '__all__'
        exclude = ['owner', ]


class TestSerialiser(serializers.Serializer):
    class Meta:
        model = Contact
        exclude = ['owner', ]
