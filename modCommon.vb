Imports System
Imports Newtonsoft.Json
Imports System.Security.Cryptography
Imports System.IO


Module modCommon
    Public Function col5CLI(arg1$, arg2$, arg3$, arg4$, Optional ByVal arg5$ = "") As String
        col5CLI = ""
        arg1 = Mid(arg1, 1, 34)
        arg2 = Mid(arg2, 1, 24)
        col5CLI = arg1 + spaces(35 - Len(arg1)) + arg2 + spaces(25 - Len(arg2)) + arg3 + spaces(10 - Len(arg3))
        col5CLI += arg4 + spaces(10 - Len(arg4)) + arg5 + spaces(10 - Len(arg5))


    End Function

    Public Function fLine(arg1$, arg2$, Optional ByVal numSpaces As Integer = 25) As String
        Return arg1 + spaces(numSpaces - Len(arg1)) + arg2
    End Function


    Public Function inStrList(ByRef L As List(Of String), theStr$, Optional ByVal caseSensitive As Boolean = False) As Boolean
        inStrList = False

        If caseSensitive = False Then
            theStr = LCase(theStr)
        End If

        For Each S In L
            If caseSensitive = False Then S = LCase(S)
            If S = theStr Then
                Return True
                Exit Function
            End If
        Next
    End Function

    Public Function inIntList(ByRef L As List(Of Integer), theNum As Integer) As Boolean
        inIntList = False

        For Each nuM In L
            If nuM = theNum Then
                Return True
                Exit Function
            End If
        Next
    End Function

    Public Function trimVal(ByVal a$, Optional ByVal sStr As String = "{},") As String
        trimVal = ""
        Dim b$ = ""
        Dim K As Long = 0

        For K = 1 To Len(a)
            b$ = Mid(a, K, 1)
            If InStr(sStr, b) Then
                Return trimVal
            Else
                trimVal += b
            End If
        Next

    End Function

    Public Function allTextAfter(ByVal a$, Optional ByVal stopChr$ = "(") As String
        allTextAfter = ""
        Dim b$ = ""
        Dim newS$ = ""

        Dim addChars As Boolean = False

        For K = 1 To Len(a)
            b$ = Mid(a, K, 1)
            If b$ <> stopChr Then
                If addChars = True Then newS += b
            Else
                If addChars = True Then newS += b
                addChars = True
            End If
        Next

        Return newS
    End Function
    Public Function returnInsideObjects(ByVal a$) As String
        ' something something here (inside objects, whatever(is here)) as something
        ' becomes inside objects, whatever(is here)
        returnInsideObjects = ""
        Dim b$ = ""

        b$ = allTextAfter(a)
        b$ = StrReverse(b)
        b = allTextAfter(b, ")")

        Return StrReverse(b)
    End Function

    Public Function numLayersOfString(ByVal a$) As Integer
        Return countChars(a, "(")
    End Function

    Public Function returnOutsideObject(ByVal a$) As String
        returnOutsideObject = ""

        If InStr(a, ") As ") = 0 Then
            Return ""
        End If

        Return Mid(a, InStr(a, ") As ") + 1)
    End Function
    Public Function jsonGetNear(ByVal bigString$, ByVal searchStr$, findKey$) As String
        ' look in big string for search str.. Once found, trim to { before search str to } after - then find findKey and return value.
        jsonGetNear = ""

        Dim searchChr As Integer = InStr(bigString, searchStr)
        If searchChr = 0 Then Exit Function

        Dim stringAfter$ = ""
        Dim stringBefore$ = ""

        Dim K As Integer = 0

        Dim a$ = ""
        Dim b$ = ""
        Dim chrNdx As Integer = searchChr

        b$ = Mid(bigString, chrNdx, 1)
        Do Until chrNdx > Len(bigString) Or b$ = "}"
            a$ += b
            chrNdx += 1
            b$ = Mid(bigString, chrNdx, 1)
        Loop

        chrNdx = searchChr - 1
        b$ = Mid(bigString, chrNdx, 1)
        Do Until chrNdx = 0 Or b$ = "{"
            a$ = b + a
            chrNdx -= 1
            b$ = Mid(bigString, chrNdx, 1)
        Loop

        Dim L As List(Of String)
        L = jsonValues(a, findKey)

        If L.Count Then Return L(0)
    End Function
    Public Function jsonValues(ByVal bigString$, ByVal keyName$) As List(Of String)
        jsonValues = New List(Of String)

        Dim currChr As Long = 1
        Dim valsFound As New Collection 'must store unique values as replace func will be used.. should only use replace once per unique k/v pair

loopHere:
        Dim founD As Long = 0
        founD = InStr(bigString, keyName)

        If founD = 0 Then
            Exit Function
        End If

        bigString = Mid(bigString, founD)
        Dim valString = Mid(bigString, InStr(bigString, ":") + 1) ', InStr(bigString, ",") - 1)

        If LCase(keyName) = "protocolids" Then
            valString = trimVal(valString, "]")
        Else
            valString = trimVal(valString)
        End If

        If grpNDX(valsFound, valString) = 0 Then
            jsonValues.Add(LTrim(valString))
            valsFound.Add(LTrim(valString))
        End If
        bigString = Mid(bigString, InStr(bigString, valString) + 2)

        GoTo loopHere
    End Function

    Public Function ndxLIST(lbl$, L As List(Of String)) As Integer
        ndxLIST = -1

        lbl = LCase(lbl)

        Dim ndX As Integer = 0
        For Each P In L
            If LCase(P) = lbl Then
                Return ndX
                Exit Function
            End If
            ndX += 1
        Next

    End Function

    Public Function csvTOquotedList(ByVal a$, Optional ditchQuotes As Boolean = False) As String
        Dim b$ = ""

        Dim C As Object
        C = Split(a, ",")

        Dim d$
        d = Chr(34)
        If ditchQuotes = True Then d = ""

        Dim K As Integer
        For K = 0 To UBound(C)
            b += d + C(K) + d + ","
        Next

        b = Mid(b, 1, Len(b) - 1)
        Return b$
    End Function


    Public Function argValue(lookForArg$, ByRef theArgs$()) As String
        ' assumes format "--arg value"
        Dim argNum As Integer = 0

        For Each A In theArgs
            argNum += 1
            'Console.WriteLine(A)
            If LCase(A) = LCase("--" + lookForArg) Then
                If argNum + 1 > theArgs.Count Then Return ""
                'Console.WriteLine("foundit")
                Return theArgs(argNum)
            End If
        Next
        Return ""
    End Function

    Public Function argExist(lookForArg$, ByRef theArgs$()) As String
        ' assumes format "--arg value"
        argExist = False

        For Each A In theArgs
            If LCase(A) = LCase(lookForArg) Then
                Return True
            End If
        Next
        Return False
    End Function


    Public Function grpNDX(ByRef C As Collection, ByRef a$, Optional ByVal caseSensitive As Boolean = True) As Integer
        Dim K As Long
        grpNDX = 0

        If C.Count = 0 Then Exit Function
        If caseSensitive = False Then GoTo dontEvalCase

        For K = 1 To C.Count
            If a = C(K) Then
                grpNDX = K
                Exit Function
            End If
        Next
        Exit Function

dontEvalCase:
        For Each S In C
            K += 1
            If LCase(a) = LCase(S) Then
                grpNDX = K
                Exit Function
            End If
        Next


    End Function

    Public Function safeFilename(ByVal a) As String
        safeFilename = Replace(a, "\", "")
        safeFilename = Replace(safeFilename, "..", "")
    End Function


    Public Function listNDX(ByRef C As List(Of String), ByRef a$) As Integer
        Dim K As Integer = 0
        listNDX = 0

        For K = 0 To C.Count - 1
            If C(K).ToString = a Then
                listNDX = K + 1
                Exit Function
            End If
        Next

    End Function

    Public Function jsonKV(k$, v$, Optional ByVal noQ As Boolean = False) As String
        'stop using this function
        Dim c$ = Chr(34)
        'c$ = ""
        Dim keYv$ = c + k + c + ": "
        Dim vaLu$ = ""
        If noQ = False Then vaLu = c + v + c Else vaLu = v
        Return keYv + vaLu
    End Function

    Public Function arrNDX(ByRef A$(), ByRef matcH$) As Integer
        'returns 0 if not found, otherwise NDX + 1
        Dim K As Long
        arrNDX = 0
        For K = 0 To UBound(A)
            If Trim(Str(A(K))) = matcH Then
                arrNDX = K + 1
                Exit Function
            End If
        Next
    End Function
    Public Function spaces(howmany As Integer) As String
        spaces = ""
        Dim K As Integer
        For K = 1 To howmany
            spaces += " "
        Next
    End Function
    Public Function removeExtraSpaces(a) As String
        removeExtraSpaces = ""
        If Len(a) = 0 Then Exit Function
        Dim lastSpace As Boolean = False

        Dim K As Integer = 0
        For K = 0 To Len(a) - 1
            If lastSpace = False Then
                removeExtraSpaces += Mid(a, K + 1, 1)
            Else
                If Mid(a, K + 1, 1) <> " " Then removeExtraSpaces += Mid(a, K + 1, 1)
            End If
            If Mid(a, K + 1, 1) = " " Then
                lastSpace = True
            End If
        Next

    End Function

    Public Function countChars(a$, chr2Count$) As Integer
        countChars = 0

        Dim K As Integer = 0
        For K = 0 To Len(a) - 1
            If Mid(a, K + 1, 1) = chr2Count Then countChars += 1
        Next
    End Function

    Public Function stripToFilename(ByVal fileN$) As String
        'C:\Program Files\Checkmarx\Checkmarx Jobs Manager\Results\WebGoat.NET.Default 2014-10.9.2016-19.59.35.pdf
        stripToFilename = ""

        Do Until InStr(fileN, "\") = 0
            fileN = Mid(fileN, InStr(fileN, "\") + 1)
        Loop

        stripToFilename = fileN

    End Function

    Public Function addSlash(ByVal a$) As String
        addSlash = a
        If Len(a) = 0 Then Exit Function

        If Mid(a, Len(a), 1) <> "\" Then addSlash += "\"
    End Function

    Public Function getParentGroup(ByVal g$) As String
        Dim a$ = StrReverse(g)
        a = Mid(a, InStr(a, "\") + 1)
        Return StrReverse(a)
    End Function

    Public Function stripLastWord(ByVal g$) As String
        Dim a$ = StrReverse(g)
        a = Mid(a, InStr(a, " ") + 1)
        Return StrReverse(a)
    End Function


    Public Function assembleCollFromCLI(clI$) As Collection
        Dim C As New Collection
        ' takes windows dos-style dir output and makes sense of it for collection storage
        Dim tempStr$ = clI
        Dim K As Integer
        Do Until InStr(tempStr, "  ") = 0
            K = InStr(tempStr, "  ")
            If Len(Mid(tempStr, 1, K - 1)) Then C.Add(Mid(tempStr, 1, K - 1))
            tempStr = Replace(tempStr, Mid(tempStr, 1, K - 1) + "  ", "")
            'Debug.Print(tempStr)
        Loop
        tempStr = LTrim(tempStr)
        C.Add(Mid(tempStr, 1, InStr(tempStr, " ") - 1))
        tempStr = Replace(tempStr, Mid(tempStr, 1, InStr(tempStr, " ") - 1), "")
        C.Add(LTrim(tempStr))
        Return C

    End Function

    Public Function numCHR(ByVal cS$, whichCHR$) As Integer
        numCHR = 0
        If Len(cS) = 0 Then Exit Function
        Dim K As Integer
        For K = 1 To Len(cS)
            If Mid(cS, K, 1) = whichCHR Then numCHR += 1
        Next
    End Function

    Public Function CSVtoCOLL(ByRef csV$) As Collection
        CSVtoCOLL = New Collection

        Dim splitCHR$ = ","
        If InStr(csV, splitCHR) = 0 Then splitCHR = ";"


        Dim longS = Split(csV, splitCHR)

        Dim K As Integer
        For K = 0 To UBound(longS)
            CSVtoCOLL.Add(longS(K))
        Next

    End Function


    Public Function CSVFiletoCOLL(ByRef csV$) As Collection
        CSVFiletoCOLL = New Collection
        If Dir(csV) = "" Then Exit Function

        'use file
        Dim FF As Integer
        FF = FreeFile()

        FileOpen(FF, csV, OpenMode.Input)

        Do Until EOF(FF) = True
            CSVFiletoCOLL.Add(LineInput(FF))
        Loop
        FileClose(FF)

    End Function

    Public Sub safeKILL(ByRef fileN$)
        If Dir(fileN) <> "" Then Kill(fileN)
    End Sub


    Public Function filePROP(fileN$, proP$) As String
        filePROP = ""
        If Dir(fileN) = "" Then Exit Function

        If Len(proP) = 0 Then Exit Function

        Dim FF As Integer = FreeFile()

        FileOpen(FF, fileN, OpenMode.Input, OpenAccess.Read, OpenShare.Shared)

        Dim a$ = ""

        a = LineInput(FF)
        Do Until a = "" Or EOF(FF) = True
            If InStr(a, "=") = 0 Then GoTo nextLine

            If UCase(proP) = Mid(a, 1, InStr(a, "=") - 1) Then
                filePROP = Replace(a, proP + "=", "")
            End If
nextLine:
            a = LineInput(FF)
        Loop

        If Len(a) = 0 Then GoTo closeHere

        If UCase(proP) = Mid(a, 1, InStr(a, "=") - 1) Then
            filePROP = Replace(a, proP + "=", "")
        End If

closeHere:

        FileClose(FF)
    End Function

    Public Function allObjectsToList(fileN$) As List(Of String)
        allObjectsToList = New List(Of String)
        Dim C As New Collection
        Call getAllObjNamesFromFile(fileN, C)

        For Each A In C
            allObjectsToList.Add(loadOBJfromFILE(fileN, A))
        Next
    End Function

    Public Sub allObjectsWithProp(ByRef objS As List(Of String), prop$, propValue$, ByRef coll2Fill As Collection)
        coll2Fill = New Collection

        For Each O In objS
            If UCase(objProp(O, UCase(prop))) = UCase(propValue) Then coll2Fill.Add(objProp(O, "NAME"))
        Next
    End Sub



    Public Sub getAllObjNamesFromFile(fileN$, ByRef collOFnames As Collection)
        collOFnames = New Collection

        If Dir(fileN) = "" Then Exit Sub

        Dim FF As Integer = FreeFile()

        FileOpen(FF, fileN, OpenMode.Input, OpenAccess.Read, OpenShare.Shared)

        Dim a$ = ""

        a = LineInput(FF)
        Do Until EOF(FF) = True
            If UCase(Mid(a, 1, 5)) = "NAME=" Then
                collOFnames.Add(Replace(a, "NAME" + "=", ""))
            End If
            a = LineInput(FF)
        Loop

        FileClose(FF)

    End Sub

    Public Function loadOBJfromFILE(fileN$, objName$) As String
        loadOBJfromFILE = ""

        If Dir(fileN) = "" Then Exit Function

        If Len(objName) = 0 Then Exit Function

        Dim FF As Integer = FreeFile()

        FileOpen(FF, fileN, OpenMode.Input, OpenAccess.Read, OpenShare.Shared)

        Dim a$ = ""
        Dim buildStr$ = ""

        Dim findSTR$ = "NAME=" + UCase(objName)

        a = LineInput(FF)
        Do Until UCase(a) = findSTR Or EOF(FF) = True
nextLine:
            a = LineInput(FF)
        Loop

        If UCase(a) = findSTR Then
            Do Until a = "" Or EOF(FF) = True
                buildStr += a + vbCrLf
                a = LineInput(FF)
            Loop
        End If

        loadOBJfromFILE = buildStr
        FileClose(FF)


    End Function

    Public Function objProp(ByRef ObjString As String, propName$) As String
        objProp = ""
        Dim findS$ = UCase(propName) + "="

        Dim O = Split(ObjString, vbCrLf)

        If UBound(O) = 0 Then Exit Function

        Dim K As Integer

        For K = 0 To UBound(O)
            If Mid(O(K), 1, Len(findS)) = UCase(propName) + "=" Then
                'found object, return property
                objProp = Mid(O(K), InStr(O(K), "=") + 1)
                Exit Function
            End If
        Next

    End Function


    Public Function xlsDataType(dType$) As String
        xlsDataType = "nonefound"
        Select Case dType
            Case "bigint", "int", "numeric", "float"
                xlsDataType = "Numeric"
            Case "datetime", "datetime2"
                xlsDataType = "DateTime"
            Case "date"
                xlsDataType = "Date"
            Case "time"
                xlsDataType = "Time"
            Case "bit"
                xlsDataType = "Boolean"
            Case "ntext", "nvarchar", "nchar", "varchar", "image", "uniqueidentifier", "real"
                xlsDataType = "String"
        End Select
        If xlsDataType = "nonefound" Then
            Debug.Print("No Def: " + dType)
            xlsDataType = "String"
        End If
    End Function

    Public Function xlsColName(colNum As Integer) As String
        Dim d As Integer
        Dim m As Integer
        Dim name As String
        d = colNum
        name = ""
        Do While (d > 0)
            m = (d - 1) Mod 26
            name = Chr(65 + m) + name
            d = Int((d - m) / 26)
        Loop
        xlsColName = name
    End Function

    Public Function cleanJSON(json$) As String
        If Len(json) = 0 Then Return ""

        json = Mid(json, InStr(json, "["))
        If Mid(json, Len(json), 1) = "}" Then json = Mid(json, 1, Len(json) - 1)
        json = Replace(json, "null", "0")
        'Console.WriteLine("CLEAN:" + vbCrLf + json)
        Return json


    End Function


    Public Sub saveJSONtoFile(jsonString$, ByVal errFN$) ', ByRef add2zip As Collection)

        Dim fileN$ = errFN

        Call safeKILL(fileN)
        Call streamWriterTxt(fileN, jsonString)

        '        add2zip.Add(fileN)

        GC.Collect()

    End Sub

    Public Function streamWriterTxt(fileN$, string2write$) As Boolean
        streamWriterTxt = True
        On Error GoTo errorCatch
        Dim fS As New FileStream(fileN, FileMode.OpenOrCreate, FileAccess.Write)
        Dim sW As New StreamWriter(fS)
        sW.BaseStream.Seek(0, SeekOrigin.End)
        sW.WriteLine(string2write$)
        sW.Flush()
        sW.Close()

        sW = Nothing
        fS = Nothing

        Exit Function

errorCatch:
        streamWriterTxt = False
        sW = Nothing
        fS = Nothing


    End Function

    Public Function streamReaderTxt(fileN$) As String
        streamReaderTxt = ""
        Dim fS As New FileStream(fileN, FileMode.Open, FileAccess.Read)
        Dim sR As New StreamReader(fS)

        Do Until sR.EndOfStream() = True
            streamReaderTxt += sR.ReadLine() + vbCrLf
        Loop

        sR = Nothing
        fS = Nothing
    End Function
    Public Function cleanJSONright(json$) As String
        ' sometimes additional info 'stacked' onto json array.. doing this rather than customizing objects.. back up to ]
        Dim K As Integer = Len(json)
        Dim a$ = Mid(json, K, 1)

        json = Mid(json, 1, InStr(json, "linkDataArray") - 1)

        Do Until a$ = "]" Or Len(json) < 1
            K = K - 1
            json = Mid(json, 1, K)
            a$ = Mid(json, K, 1)
        Loop


        Return json
    End Function

    Public Function getJSONObject(key$, json$) As String
        On Error GoTo errorcatch

        Dim sObject = JsonConvert.DeserializeObject(json)
        Return sObject(key)

errorcatch:
        Return ""
    End Function

    Public Function previousWord(W$, Optional ByVal toSpace As String = " ") As String
        previousWord = ""
        Dim a$ = ""
        Dim K As Integer = 0

        For K = Len(W) To 1 Step -1
            a$ = Mid(W, K, 1)
            If a = toSpace Then
                Return previousWord
            Else
                previousWord = a + previousWord
            End If
        Next

    End Function

    Public Function noComma(S As String) As String
        noComma = S
        If countChars(S, ",") = 0 Then Return noComma
        If Mid(S, Len(S), 1) = "," Then Return Mid(S, 1, Len(S) - 1)
    End Function

End Module
