from django.shortcuts import render
from rest_framework import generics, permissions
from .serializers import ContactSerializer
from .models import Contact
from .paginations import CustomPagination
from .permissions import IsOwner


class ContactList(generics.ListCreateAPIView):
    serializer_class = ContactSerializer
    permission_classes = [permissions.IsAuthenticated, ]
    pagination_class = CustomPagination

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

    def get_queryset(self):
        if isinstance(self.request.user.id, int):
            return Contact.objects.filter(owner=self.request.user)


class ContactDetails(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = ContactSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwner]

    def get_queryset(self):
        if isinstance(self.request.user.id, int):
            return Contact.objects.filter(owner=self.request.user)
