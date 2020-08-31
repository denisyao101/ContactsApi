from rest_framework import pagination


class CustomPagination(pagination.PageNumberPagination):
    page_size = 25
    page_query_param = 'page_size'
    max_page_size = 100
