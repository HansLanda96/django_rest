from django.urls import path

from .views import author_create, author_detail, author_list


app_name = "shelf"

urlpatterns = [
    path("author/", author_list, name='author-list'),
    path("author_add/", author_create, name='author-add'),
    path('author_detail/<int:pk>/', author_detail, name='author-detail')
]
