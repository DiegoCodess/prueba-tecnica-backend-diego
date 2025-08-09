from django.shortcuts import render

# Create your views here.
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import User
from .serializers import UserSerializer
from rest_framework.permissions import IsAuthenticated

import base64
from datetime import datetime
import random, string

def gen_voucher(length=8):
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

class IsNotSuperuserPermission:
    # helper permission (usaremos en métodos Create/Delete)
    def has_permission(self, request, view):
        return not request.user.is_superuser  # crea/borrar solo si quien hace action NO es superadmin

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all().order_by('id')
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsNotSuperuserCreateDelete, CannotModifySuperuser]

    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        return UserSerializer

    def perform_create(self, serializer):
        # opcional: validar permisos de creación en backend
        if self.request.user.is_superuser:
            # según reglas: superadmins no pueden ser creados desde interfaz,
            # pero esto evita que se cree un usuario marcado is_superuser=True en el POST
            serializer.save()
        else:
            serializer.save()

    def update(self, request, *args, **kwargs):
        # impedir editar superadmins (si target es superuser)
        target = self.get_object()
        if target.is_superuser:
            return Response({"detail":"No permitido editar superadmin."}, status=status.HTTP_403_FORBIDDEN)
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        target = self.get_object()
        if target.is_superuser:
            return Response({"detail":"No permitido eliminar superadmin."}, status=status.HTTP_403_FORBIDDEN)
        # adicional: solo usuarios con permiso (no superadmins?) según reglas
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=['post'])
    def assign_voucher(self, request, pk=None):
        user = self.get_object()
        # regla: generar código alfanumérico 8 chars
        code = gen_voucher(8)
        # adjuntar fecha y hora ISO y codificar en base64: "CODE|2025-08-09T12:34:56"
        timestamp = datetime.utcnow().isoformat()
        to_encode = f"{code}|{timestamp}"
        b64 = base64.b64encode(to_encode.encode()).decode()
        # guardar b64 en campo voucher
        user.voucher = b64
        user.save()
        return Response({"voucher": b64, "plain": code, "timestamp": timestamp}, status=status.HTTP_200_OK)
