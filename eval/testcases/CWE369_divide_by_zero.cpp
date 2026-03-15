int average(int* arr, int count) {
    int sum = 0;
    for (int i = 0; i < count; i++) sum += arr[i];
    return sum / count; // division by zero when count == 0
}
