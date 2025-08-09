from rest_framework import permissions

class IsNotSuperuserCreateDelete(permissions.BasePermission):
    """
    Permite crear/eliminar solo si el usuario que hace la petición NO es superuser.
    (Regla dada en el enunciado: "Crear y Eliminar solo visibles para usuarios que no son Superadmin")
    """
    def has_permission(self, request, view):
        # Solo aplica a métodos POST (create) y DELETE (handled in object-level has_object_permission)
        if request.method in ['POST', 'DELETE']:
            return not request.user.is_superuser
        return True

class CannotModifySuperuser(permissions.BasePermission):
    """Evita editar/eliminar usuarios que son superusers."""
    def has_object_permission(self, request, view, obj):
        # Si el objetivo es superuser, no permitir PUT/PATCH/DELETE
        if getattr(obj, 'is_superuser', False) and request.method in ['PUT', 'PATCH', 'DELETE']:
            return False
        return True