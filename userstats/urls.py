from .views import ExpenseSummaryStats, IncomeSummaryStats
from django.urls import path


urlpatterns = [
    path('expenses-category-data/', ExpenseSummaryStats.as_view(), name = "expenses-category-data"),
    path('income-source-data/', IncomeSummaryStats.as_view(), name = "income-source-data"),
]