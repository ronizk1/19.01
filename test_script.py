# test_script.py

import requests

url = 'http://127.0.0.1:5000/add_book'
headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcwNTM1NzUxOCwianRpIjoiOTQwY2I3OWItMmYwNC00M2E4LWEyMjMtYWJjNTgyOWU2NzU5IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6MywibmJmIjoxNzA1MzU3NTE4LCJjc3JmIjoiNWVhMzQ4MTUtZjY4Ny00MGM0LWE2ZjktOTQwZWYzY2ExMTAwIiwiZXhwIjoxNzA1MzYxMTE4fQ.7P5Am6YrI6eeYy4tesk689tHylAAU7AmtCzqKSBIdKA'
}
data = {
    'name': 'BookName',
    'author': 'AuthorName',
    'year_published': 2022,
    'book_type': 1
}

response = requests.post(url, json=data, headers=headers)
print(response.json())
