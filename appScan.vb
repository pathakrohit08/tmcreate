Imports Newtonsoft.Json
Imports Newtonsoft.Json.Linq


Public Class appScan
    Private sourceDirectory$
    Private fileBlockFilter$
    Private methodCounter As Counter
    Private fileCounter As Counter
    Private containerCounter As Counter
    Private graphCounter As Counter

    Private depthChangers As Collection
    Private methodDescriptors As Collection

    Private sourceFiles As List(Of SourceFile)
    Private codeContainers As List(Of CodeCollection)

    Private allMethods As List(Of Method)
    'Private allClasses As List(Of ClassS)

    Private onlyFiles As String
    Private onlyPublic As Boolean
    Private classWatch As String
    Private methodWatch As String
    Private maxDepth As Integer

    Private modelType As String

    Public bestMethod As String
    Public bestRMethod As String
    Public bestCC As String
    Public bestCL As String
    Public bestSF As String

    Private Class Counter
        Private currCount As Integer

        Public Sub New()
            currCount = 0
        End Sub

        Public Function addOne() As Integer
            currCount += 1
            Return currCount
        End Function
        Public Function getCount() As Integer
            Return currCount
        End Function
    End Class

    Private Class CodeCollection
        Public Id As Integer
        Public sourceFilename$
        Public ccType$ ' eg 'Module', 'Class'. 'File'
        Public Name$
        'Public deptH As Integer
        Public patH As String
        Public ofParents As String
        Public graphId As Integer
        Public isPublic As Boolean
        Public sourceLines As List(Of String)
        Public allMethods As List(Of Method)
        '        Public allClasses As List(Of String)

        Public classRefs As List(Of classInst)
        Public mappingRefs As List(Of classInst)

        Public createsClasses As List(Of String)
        Public usesMethods As List(Of String)

        Public Sub New()
            allMethods = New List(Of Method)
            'allClasses = New List(Of String)

            sourceLines = New List(Of String)
            classRefs = New List(Of classInst)
            createsClasses = New List(Of String)
            usesMethods = New List(Of String)
            mappingRefs = New List(Of classInst)
        End Sub

        'Public Function totalLOC() As Long
        '    totalLOC = sourceLines.Count
        '    For Each M In allMethods
        '        totalLOC += M.sourceLines.Count
        '    Next
        'End Function
    End Class

    Private Class Method
        Public Id As Integer
        Public Name As String
        Public sourceFilename$
        Public isPublic As Boolean
        Public doesReturn As Boolean
        Public returnType As String
        Public graphId As Integer
        Public patH As String
        Public ofParent As String 'what parents (csv) does this method belong to?
        Public parametersExpected As String
        Public sourceLines As List(Of String)

        Public classRefs As List(Of classInst)
        Public mappingRefs As List(Of classInst)

        Public createsClasses As List(Of String)
        Public usesMethods As List(Of String)
        Public returnsTo As List(Of String)
        Public Sub New()
            sourceLines = New List(Of String)
            classRefs = New List(Of classInst)
            createsClasses = New List(Of String)
            usesMethods = New List(Of String)
            returnsTo = New List(Of String)
            mappingRefs = New List(Of classInst)
        End Sub
    End Class

    Private Class searchMethods
        Public searchStr As String
        Public sourcePath As String
        Public scopE As String
    End Class
    Private Class classInst
        Public varName As String
        Public classPath As String
        Public isPublic As Boolean
        Public scopE As String
    End Class
    Private Class Parameter
        Public Name As String
        Public pType As String
        Public isRequired As Boolean
    End Class

    Private Class SourceFile
        Public Id As Integer
        'Public allMethods As List(Of Method)
        'Public allClasses As List(Of ClassS)
        'Public graphId As Integer
        Public fileName$
        Public linesOfCode$
        Public LOC As Long 'lines of code

        Public Sub New(fileN$, unqID As Integer, graphNdx As Integer)
            'allMethods = New List(Of Method)
            'allClasses = New List(Of ClassS)
            fileName = fileN
            Id = unqID
            'graphId = graphNdx
        End Sub
    End Class

    Private Class ClassS
        Public Name As String
        Public sourceFilename$
        Public isPublic As Boolean
        Public path As String
        Public ofParent As String 'could be blank if depth=1
        'Public classObjects As List(Of ClassObj)
        'Public usedBy As List(Of Method)
        Public graphId As Integer
        'Public classRefs As List(Of classInst)
        Public Sub New()
            '    classRefs = New List(Of classInst)
        End Sub

    End Class


    Public Function doScan(dirToScan$, files2Block$, Optional ByVal objects2Watch$ = "", Optional ByVal mType$ = "", Optional ByVal files2show$ = "", Optional ByVal maximumDepth As Integer = 0, Optional ByVal showClients As Boolean = False) As String
        ' I think these globals are unnecessary - confirm
        'resulT1 = nScan.doScan(sDir, block, objectsToWatch, modelType, showOnlyFiles, maxDepth)

        ' whole
        ' objmap - structuremap
        ' classwatch - singleclass
        ' clients - callers
        ' public - property
        If mType = "" Then modelType = "full"
        If mType = "methodmap" Then methodWatch = objects2Watch
        If mType = "classmap" Then classWatch = objects2Watch
        If mType = "public" Then onlyPublic = True

        modelType = mType

        Dim showOnlyClasses As Boolean = False
        If mType = "classmap" Then showOnlyClasses = True

        onlyFiles = files2show
        maxDepth = maximumDepth

        methodCounter = New Counter
        fileCounter = New Counter
        containerCounter = New Counter
        graphCounter = New Counter

        codeContainers = New List(Of CodeCollection)
        sourceFiles = New List(Of SourceFile)
        allMethods = New List(Of Method)
        'allClasses = New List(Of ClassS)

        Dim allJsonObjects As List(Of makeTMJson.tmObject) = New List(Of makeTMJson.tmObject)

        Call getSourceFiles(dirToScan, files2Block)


        For Each S In sourceFiles
            Call loadCode(S)
            'Console.WriteLine("[ID " + S.Id.ToString + "/LOC " + S.LOC.ToString + "/CHR " + Len(S.linesOfCode).ToString + "]: " + S.fileName)

            Dim CC As New CodeCollection
            With CC
                .Name = stripToFilename(S.fileName)
                '.deptH = 0
                .patH = "|FILE|" + S.fileName
                .ccType = "File"
                .Id = containerCounter.addOne
                .graphId = graphCounter.addOne
                .sourceFilename = S.fileName
                .ofParents = ""
            End With
            codeContainers.Add(CC)
        Next

        Dim K As Integer = 0
        For K = 0 To sourceFiles.Count - 1
            Call scanCodeForStructure(K)
            sourceFiles(K).linesOfCode = ""
            ' this code is copied from sourcefile object to codecollection object
            GC.Collect()
        Next K

        Call scanCodeForClassMapping()
        Call scanCodeForMethodMapping()

        '     For Each cc In codeContainers
        '         If cc.allMethods.Count Then Console.WriteLine("[" + cc.graphId.ToString + "/" + cc.totalLOC.ToString + " LOC/" + cc.allMethods.Count.ToString + " Methods]: " + cc.patH)
        '     Next


        Dim newTM As makeTMJson = New makeTMJson


        Dim jSon$ = ""

        allJsonObjects = newTM.getJSONobjects(Me, showOnlyClasses)

        Console.WriteLine("# of Objects in Class/Method Map: " + allJsonObjects.Count.ToString)

        Dim allFilteredObjects As List(Of makeTMJson.tmObject) = New List(Of makeTMJson.tmObject)

        'allJson = every object
        'here we do the slicing according to depth
        If Len(objects2Watch) Then
            Dim CH As List(Of Integer)
            If showOnlyClasses Then
                CH = buildChosenObjects(allJsonObjects, objects2Watch, "")
            Else
                CH = buildChosenObjects(allJsonObjects, "", objects2Watch)
            End If

            If CH.Count = 0 Then
                Dim eMsg$ = "ERROR: No matches found in class/method objects"
                Console.WriteLine(eMsg)
                Return eMsg
                Exit Function
                '    Else
                '        Console.WriteLine("Matched " + CH.Count.ToString + " objects")
            End If

            allFilteredObjects = newTM.buildSlice(allJsonObjects, CH, maximumDepth, showClients)
            jSon = JsonConvert.SerializeObject(allFilteredObjects)
        Else
            jSon = JsonConvert.SerializeObject(allJsonObjects)
        End If


        Call safeKILL("jsonfile.json")
        saveJSONtoFile(jSon, "jsonfile.json")

        Return CurDir() + "\jsonfile.json"
        'Console.WriteLine(jSon)
    End Function

    Private Function buildChosenObjects(ByRef allObj As List(Of makeTMJson.tmObject), classeS$, methodS$) As List(Of Integer)
        buildChosenObjects = New List(Of Integer)
        Dim c2W As New Collection
        Dim m2W As New Collection

        c2W = CSVtoCOLL(classeS)
        m2W = CSVtoCOLL(methodS)

        For Each MM In allMethods
            If grpNDX(m2W, MM.Name, False) Then
                buildChosenObjects.Add(MM.graphId)
                ' For Each userOfMethod In 
            End If
        Next

        For Each CC In codeContainers
            If grpNDX(c2W, CC.Name) Then
                buildChosenObjects.Add(CC.graphId)
            End If
        Next
    End Function
    Private Function ndxCodeCollection(pathOfCC) As Integer
        ndxCodeCollection = -1
        Dim ndX As Integer = 0
        For Each C In codeContainers
            If C.patH = pathOfCC Then
                Return ndX
            End If
            ndX += 1
        Next
    End Function

    Private Function ofCodeCollection(pathOfCC) As CodeCollection
        If pathOfCC = "" Then
            Return New CodeCollection
        End If
        pathOfCC = noComma(pathOfCC)

        If Mid(pathOfCC, Len(pathOfCC), 1) = "," Then pathOfCC = Mid(pathOfCC, 1, Len(pathOfCC) - 1)
        ofCodeCollection = New CodeCollection

        For Each C In codeContainers
            If C.patH = pathOfCC Then
                Return C
            End If
        Next
    End Function

    Private Function findGraphId(pathOfCC) As Integer
        pathOfCC = noComma(pathOfCC)
        findGraphId = 0
        findGraphId = ofCodeCollection(pathOfCC).graphId

        If findGraphId = 0 Then findGraphId = ofMethod(pathOfCC).graphId
        If findGraphId = 0 Then findGraphId = -1
    End Function

    Private Function ofMethod(pathOfCC) As Method
        pathOfCC = noComma(pathOfCC)

        ofMethod = New Method

        For Each C In allMethods
            If C.patH = pathOfCC Then
                Return C
            End If
        Next
    End Function


    Private Sub getSourceFiles(dirToScan$, files2Block$)
        Dim Directories As New IO.DirectoryInfo(dirToScan)
        Dim fileInfo = Directories.GetFiles("*.vb", IO.SearchOption.AllDirectories)

        Dim bC As New Collection

        bC = CSVtoCOLL(files2Block)

        For Each file In fileInfo
            Dim blockThis As Boolean = False
            For Each blk In bC
                If InStr(LCase(file.FullName), LCase(blk)) Then blockThis = True
            Next
            If blockThis = False Then
                ' These become our source files to scan
                '                Console.WriteLine("File: " + file.FullName)
                fileCounter.addOne()
                sourceFiles.Add(New SourceFile(file.FullName, fileCounter.getCount, graphCounter.addOne))
            End If
        Next
    End Sub
    Private Sub loadCode(S As SourceFile)
        S.linesOfCode = streamReaderTxt(S.fileName)
        S.LOC = countChars(S.linesOfCode, Chr(13))
        GC.Collect()
    End Sub

    Public Sub New()
        'setting up AppScan class

        'define depthChangers - these are structural changes that determine depth
        '
        ' file
        ' class XYZ    <depth 0
        ' sub         <depth 1
        ' function     < still depth 1
        ' class ABC    <depth 2
        ' sub          < depth 2 - sub of a class

        'VB stuff
        depthChangers = New Collection
        depthChangers.Add("Public Class ")
        depthChangers.Add("Private Class ")
        depthChangers.Add("Module ")
        depthChangers.Add("Class ")
        depthChangers.Add("End Class")
        depthChangers.Add("End Module")
        depthChangers.Add("Public NotInheritable Class ")
        depthChangers.Add("Private NotInheritable Class ")

        methodDescriptors = New Collection
        methodDescriptors.Add("Public Sub ")
        methodDescriptors.Add("Private Sub ")
        methodDescriptors.Add("Public Function ")
        methodDescriptors.Add("Private Function ")
        methodDescriptors.Add("Function ")
        methodDescriptors.Add("Sub ")
        methodDescriptors.Add("End Function")
        methodDescriptors.Add("End Sub")

        graphCounter = New Counter

    End Sub

    Private Function removeScope(ByVal scopeStr$) As String
        removeScope = ""
        ' scope is |A|Upper Lvl Obj,|B|Secondary,|C|Tertiary and so on
        'removing pulls off outermost object

        If InStr(scopeStr, ",") = 0 Then Return ""

        If Mid(scopeStr, Len(scopeStr), 1) = "," Then scopeStr = Mid(scopeStr, 1, Len(scopeStr) - 1)

        Dim C As New Collection
        C = CSVtoCOLL(scopeStr)

        Dim newScope$ = ""
        Dim K As Integer = 0

        For K = 1 To C.Count - 1
            newScope += C(K) + ","
        Next

        Return newScope
    End Function
    Private Sub scanCodeForStructure(ByVal sourceNum As Integer)

        With sourceFiles(sourceNum)

            Dim chrNum As Long = 1
            Dim LOC$ = ""
            Dim currScope$ = ""
            Dim deptH As Integer = 0

            Dim foundSomething As Boolean
            Dim nameOfObj$ = ""
            Dim methParams$ = ""

            Dim currMethod As Integer = 0

            Dim currPath As String = ""
            Dim inMethod As Boolean = False

            Dim currPathCC As Integer = 0
            currPathCC = ndxCodeCollection("|FILE|" + sourceFiles(sourceNum).fileName)

            currScope = codeContainers(currPathCC).patH + ","

            If InStr(.linesOfCode, Chr(13)) = 0 Then
                Exit Sub
            End If


            ' depth at file level is 0
            ' some languages (python) put executable code at depth 0, though first many lines of code are methods
            ' others (.net) put their dependency imports at depth 0
            ' |FILE| |MOD| |CLASS| |METHOD|
            ' currScope string will follow depth integer
            ' increases any time parser goes deeper into a MOD CLASS METHOD
            ' Path string navigation will determine grouping of model components
            ' source stored to either codecollection or method

            ' also build classRefs list
            ' represents variables declared as classes

            LOC = Mid(.linesOfCode, chrNum, InStr(Mid(.linesOfCode, chrNum), Chr(13)))
            chrNum += Len(LOC)

            Do Until InStr(LOC, Chr(13)) = 0
                'Console.WriteLine(Mid(LOC, 1, Len(LOC) - 1)) ' -1 to avoid extra LF

                If Len(LTrim(LOC)) Then
                    If Mid(LTrim(LOC), 1, 1) = "'" Then GoTo skipLineOfCode
                End If

                foundSomething = False
                ' here 'FoundSomething' references anything that affects current object path
                ' currscope manipulated appropriately
                For Each D In depthChangers
                    If Mid(LTrim(LOC), 1, Len(D)) = D Then
                        foundSomething = True

                        nameOfObj$ = Replace(Trim(Mid(LTrim(LOC), Len(D))), vbCr, "")

                        If Mid(LTrim(LOC), 1, 4) = "End " Then
                            deptH -= 1
                            currScope = removeScope(currScope)
                        Else
                            deptH += 1
                            Dim pFx$ = "MOD"
                            If InStr(LOC, " Class ") Then pFx = "CLS"

                            Dim CC As New CodeCollection
                            CC.sourceFilename = .fileName
                            CC.Id = containerCounter.addOne
                            CC.ofParents = noComma(currScope)
                            CC.patH = noComma(currScope) + ",|" + pFx + "|" + nameOfObj
                            CC.Name = nameOfObj
                            If InStr(LTrim(LOC), "Public ") Then CC.isPublic = True

                            If pFx = "MOD" Then
                                CC.ccType = "Module"
                            Else
                                CC.ccType = "Class"

                                '                               Dim newClass As ClassS = New ClassS
                                '                                With newClass
                                '                                    .ofParent = noComma(currScope)
                                '                                    .path = CC.patH
                                '                                    .Name = nameOfObj
                                '                                    .sourceFilename = CC.sourceFilename
                                '                                    If InStr(LTrim(LOC), "Public ") Then .isPublic = True
                                '                                    ' no graph id because class graphed as codecollection obj
                                '                                End With
                                'allClasses.Add(newClass)
                                ' adds discovered class -
                            End If
                            'CC.deptH = deptH

                            CC.graphId = graphCounter.addOne

                            codeContainers.Add(CC)

                            currScope = CC.patH + ","

                        End If

                        GoTo skipMethLook
                    End If
                Next
                For Each M In methodDescriptors
                    If Mid(LTrim(LOC), 1, Len(M)) = M Then
                        foundSomething = True

                        If Mid(LTrim(LOC), 1, 3) = "End" Or Mid(LTrim(LOC), 1, 3) = "New" Then
                            'skipping NEW constructor
                            inMethod = False
                            currScope = removeScope(currScope)
                            GoTo skipMethLook
                        End If

                        nameOfObj$ = Replace(Trim(Mid(LTrim(LOC), Len(M))), vbCr, "")

                        methParams = Mid(nameOfObj, InStr(nameOfObj, "("))
                        nameOfObj = Mid(nameOfObj, 1, InStr(nameOfObj, "(") - 1)

                        inMethod = True

                        'this is a new method
                        Dim newM As New Method
                        newM.Name = nameOfObj

                        newM.patH = noComma(currScope) + ",|METH|" + nameOfObj
                        If InStr(LTrim(LOC), "Function ") Then
                            newM.doesReturn = True
                        End If
                        newM.Id = methodCounter.addOne()
                        newM.ofParent = noComma(currScope)
                        newM.sourceFilename = .fileName
                        If Mid(methParams, 1, 2) <> "()" Then
                            '      Dim stopherenow As Integer = 1
                            ' Console.WriteLine(methParams)
                            methParams = trimVal(methParams, "'") 'remove all up to the comment
                            If newM.doesReturn Then
                                Dim oI$ = returnOutsideObject(methParams)
                                newM.returnType = Replace(oI, " As ", "")
                                methParams = Mid(methParams, 1, InStr(methParams, oI) - 1)
                            Else
                                newM.returnType = ""
                            End If
                            newM.parametersExpected = returnInsideObjects(methParams)
                        End If
                        If InStr(LTrim(LOC), "Public ") Then
                            newM.isPublic = True
                        End If
                        newM.graphId = graphCounter.addOne
                        allMethods.Add(newM)

                        currScope = newM.patH

                        GoTo skipMethLook
                    End If
                Next
skipMethLook:

                If foundSomething Then
                    Dim a$ = "FOUND SOMETHING: "
                    a += currScope
                    'Console.WriteLine(a)
                    Dim somethiung As Integer = 0

                End If


                ' Here the code is applied to either the codecollection or method
                LOC = Replace(LOC, vbCr, "")

                If inMethod = True Then
                    Dim M As Method = ofMethod(currScope)
                    M.sourceLines.Add(LOC)
                Else
                    Dim M As CodeCollection = ofCodeCollection(currScope)
                    M.sourceLines.Add(LOC)
                End If

skipLineOfCode:

                LOC = Mid(.linesOfCode, chrNum, InStr(Mid(.linesOfCode, chrNum), Chr(13)))
                chrNum += Len(LOC) + 1

            Loop

        End With

        GoTo skipDebug

        For Each cc In codeContainers
            ' Console.WriteLine("[" + cc.Id.ToString + "/" + cc.sourceLines.Count.ToString + " LOC]: " + cc.patH)

            For Each mm In allMethods
                If InStr(mm.patH, cc.patH) Then
                    'Console.WriteLine("    [" + mm.Id.ToString + "/" + mm.sourceLines.Count.ToString + " LOC]: " + mm.Name)
                End If
            Next

        Next

skipDebug:

        'keeping it this way for convenience
        'would like to loop either with global allmethods or methods ofCC
        For Each mm In allMethods
            With ofCodeCollection(mm.ofParent)
                .allMethods.Add(mm)
            End With
        Next



    End Sub

    Private Sub scanCodeForClassMapping()

        For Each CC In codeContainers
            For Each L In CC.sourceLines
                'Console.WriteLine(L)
                Dim cR As classInst = detectClassRef(L)
                If Len(cR.classPath) Then
                    cR.scopE = CC.patH
                    ' if Private, all objects of CLS or MOD can still use object
                    ' if public, all objects in all CLS or MOD can use
                    ' how can we prove association of all files to one another?
                    'Console.WriteLine("Found classref: " + CC.Name + " uses var " + cR.varName + " for class " + ofCodeCollection(cR.classPath).Name)
                    CC.classRefs.Add(cR)
                    ' probably need to add this to classs too - or keep simple?
                    addBridgeToCC(CC, cR, True)
                    ' adding connection
                End If
            Next
        Next

        ' If classesOnly Then Exit Sub 'if user selects to omit methods.. perf boost not necessary yet

        For Each MM In allMethods
            For Each L In MM.sourceLines
                'Console.WriteLine(L)
                Dim cR As classInst = detectClassRef(L)
                If Len(cR.classPath) Then
                    cR.scopE = MM.patH
                    ' a class created at method level only has scope to that method
                    ' 
                    'Console.WriteLine("Found classref: " + MM.Name + " uses var " + cR.varName + " for class " + ofCodeCollection(cR.classPath).Name)
                    MM.classRefs.Add(cR)
                    addBridgeToMethod(MM, cR, True)
                End If
            Next
        Next

    End Sub

    Private Sub scanCodeForMethodMapping()
        ' need to recognize method usage
        ' methods either called by their name or <classname>.<methodname>
        ' will need to check scope as part of process
        Dim searchList As List(Of searchMethods)
        searchList = New List(Of searchMethods)

        Dim classReferences As List(Of searchMethods) = New List(Of searchMethods)

        For Each CC In codeContainers
            For Each CR In CC.classRefs
                '                With ofMethod(CR.classPath)
                Dim sM As New searchMethods
                sM.searchStr = LCase(CR.varName)
                sM.sourcePath = CR.classPath
                If CR.isPublic = True Then sM.scopE = "" Else sM.scopE = CR.scopE
                classReferences.Add(sM)
                'Dim sM2 As New searchMethods
                'sM2.searchStr = CR.varName + "("
                'sM2.sourcePath = CR.classPath
                'searchList.Add(sM2)
                '               End With
            Next
        Next

        'now need to add all methods that are not part of a class
        For Each MM In allMethods
            ' within a class you do not have to use the <classname>.method
            If MM.Name <> "New" Then
                Dim sM As New searchMethods
                sM.searchStr = MM.Name
                sM.sourcePath = MM.patH
                sM.scopE = MM.patH
                searchList.Add(sM)
            End If
        Next


        For Each CC In codeContainers
            For Each L In CC.sourceLines
                'Console.WriteLine(L)
                Dim cR As classInst = detectMethRef(L, searchList, classReferences, CC.patH)
                If Len(cR.classPath) Then
                    cR.scopE = CC.patH
                    ' if Private, all objects of CLS or MOD can still use object
                    ' if public, all objects in all CLS or MOD can use
                    ' how can we prove association of all files to one another?
                    'Console.WriteLine("Found user: " + CC.Name + " uses method " + cR.varName + " of class/module " + ofCodeCollection(ofMethod(cR.classPath).ofParent).Name)
                    CC.mappingRefs.Add(cR)
                    ' probably need to add this to classs too - or keep simple?
                    addBridgeToCC(CC, cR)
                    ' adding connection
                End If
            Next
        Next

        For Each MM In allMethods
            For Each L In MM.sourceLines
                'Console.WriteLine(L)

                Dim cR As classInst = detectMethRef(L, searchList, classReferences, MM.patH)
                If Len(cR.classPath) Then
                    cR.scopE = MM.patH
                    ' a class created at method level only has scope to that method
                    ' 
                    'Console.WriteLine("Found user: " + MM.Name + " uses method " + cR.varName + " of class/module " + ofCodeCollection(ofMethod(cR.classPath).ofParent).Name)
                    MM.mappingRefs.Add(cR)
                    addBridgeToMethod(MM, cR)
                End If
            Next
        Next

    End Sub

    Private Sub addBridgeToCC(M As CodeCollection, cR As classInst, Optional ByVal isDeclaration As Boolean = False)
        ' bridge is either CREATE b2c9ccca-4c11-45ac-8b53-9a13577f2179
        ' or USE 3fa7bd26-7eb4-48c9-a6c5-b46b4a7e23cc
        ' or RETURN 6adacb2a-ae57-4efc-89ff-170d8fc5d5f1

        ' this routine adds 1 (and only 1) mapping between objects per create/use/return as discovered
        If isDeclaration Then
            If inStrList(M.createsClasses, cR.classPath) = False Then
                'Console.WriteLine("Adding bridge from " + M.patH + " to " + cR.classPath)
                ' this will add paths to classes created
                ' M.createsClasses.Add(cR.classPath)
            End If
        Else
            If inStrList(M.usesMethods, cR.classPath) = False Then
                M.usesMethods.Add(cR.classPath)
                With ofMethod(cR.classPath)
                    GoTo skipReturn
                    If .doesReturn Then
                        ' this is function returning something to caller
                        ' need to have path in both directions

                        'return arrows not working right :(

                        If inStrList(.returnsTo, M.patH) = False Then
                            .returnsTo.Add(M.patH)
                        End If
                    End If
skipReturn:
                End With
            End If
        End If
    End Sub

    Private Sub addBridgeToMethod(M As Method, cR As classInst, Optional ByVal isDeclaration As Boolean = False)
        ' bridge is either CREATE b2c9ccca-4c11-45ac-8b53-9a13577f2179
        ' or USE 3fa7bd26-7eb4-48c9-a6c5-b46b4a7e23cc
        ' or RETURN 6adacb2a-ae57-4efc-89ff-170d8fc5d5f1

        ' this routine adds 1 (and only 1) mapping between objects per create/use/return as discovered
        If isDeclaration Then
            If inStrList(M.createsClasses, cR.classPath) = False Then
                'M.createsClasses.Add(cR.classPath)
            End If
        Else
            If inStrList(M.usesMethods, cR.classPath) = False Then
                M.usesMethods.Add(cR.classPath)
                With ofMethod(cR.classPath)
                    GoTo skipReturn
                    If .doesReturn Then
                        ' this is function returning something to caller
                        ' need to have path in both directions

                        'return lines not working well :(

                        If inStrList(.returnsTo, M.patH) = False Then
                            .returnsTo.Add(M.patH)
                        End If
                    End If
skipReturn:
                End With
            End If
        End If
    End Sub

    Private Function detectClassRef(L$) As classInst
        ' find instantiations of classes
        ' scope determined here
        ' PRIVATE if in |MOD| or |CLS| means scope is all of that
        ' Set initial scope to MOD CLS or METH where instantiation found

        detectClassRef = New classInst
        'if classref, returns class path
        Dim maybeClass$ = ""
        Dim vName$ = ""

        If InStr(L, "(Of ") Then
            maybeClass = trimVal(Mid(L, InStr(L, "(Of ") + 4), ")")
            GoTo checkMaybe
        End If

        If InStr(L, " As ") Then ' And InStr(L, " New ") = 0 And InStr(L, "(Of ") = 0 Then
            maybeClass = Mid(L, InStr(L, " As") + 4)
            '            vName = Mid(L, 1, InStr(L, InStr(L, " As") - 1))
            '            vName = previousWord(vName)
            GoTo checkMaybe
        End If

        If InStr(L, " New ") Then
            maybeClass = Mid(L, InStr(L, " New ") + 7)
            '           vName = Replace(Replace(Replace(vName, "Public ", ""), "Private ", ""), "Dim ", "")
            GoTo checkMaybe
        End If


checkMaybe:
        If maybeClass = "" Then Exit Function

        maybeClass = Replace(Trim(maybeClass), vbCr, "")
        vName = Replace(Replace(Replace(Trim(L), "Public ", ""), "Private ", ""), "Dim ", "")
        vName = trimVal(vName, " (")

        For Each CC In codeContainers
            If CC.ccType = "Class" Then
                If maybeClass = CC.Name Then
                    ' Console.WriteLine(L + vbCrLf + "Detected classref " + vName + " " + CC.patH)
                    If vName = "Function" Then
                        Dim getFuncName$ = Replace(Mid(L, InStr(L, "Function")), "Function", "")
                        getFuncName = Trim(getFuncName)
                        getFuncName = trimVal(getFuncName, "( ")
                        vName = getFuncName
                    End If
                    With detectClassRef
                        .classPath = CC.patH
                        .varName = vName
                        If InStr(L, "Public ") Then .isPublic = True
                    End With
                End If
            End If
        Next

foundIt:
    End Function

    Private Function isValidReference(ByRef cRefs As List(Of searchMethods), LOC$, possibleMethod$) As Boolean
        isValidReference = False
        Dim singleObj$ = ""

        For Each S In cRefs
            If InStr(LOC, S.searchStr) Then
                singleObj = Mid(LOC, InStr(LOC, S.searchStr))
                singleObj = trimVal(singleObj, " ")
                ' singleObj being evaluated should be a single text object (no spaces)
                If InStr(singleObj, "." + possibleMethod) Then
                    ' short list here will include words that are subsets of method names
                    ' eg
                    ' ndxComp will register for class.ndxComp, class.ndxCompByName, class.ndxCompSomethingElse(
                    Dim methodCall$ = Mid(singleObj, InStr(singleObj, ".") + 1)
                    methodCall = trimVal(methodCall, "(")
                    If methodCall = possibleMethod Then
                        Return True
                    End If
                End If
            End If
        Next

    End Function
    Private Function detectMethRef(L$, ByRef searchList As List(Of searchMethods), ByRef classRefs As List(Of searchMethods), patH$) As classInst

        L = Trim(LCase(L))
        detectMethRef = New classInst
        'if classref, returns class path

        'no comments
        If Mid(L, 1, 1) = "'" Then Exit Function

        Dim maybeMeth$ = ""
        Dim vName$ = ""


        For Each SL In searchList
            If patH = SL.sourcePath Then GoTo notthatone
            Dim S$ = ""
            S = LCase(SL.searchStr)
            If InStr(L, S) = 0 Then GoTo notthatone

            'Console.WriteLine(L + vbCrLf)
            ' if ends in "." or "(" then need to look for methods of class


            If InStr(L, " " + S) Or Mid(L, 1, Len(S)) = S Or InStr(L, "(" + S + "(") Then
                Dim a$ = Mid(L, InStr(L, S))

                If InStr(Mid(a, 1, Len(S) + 1), S + "(") = 0 And InStr(Mid(a, 1, Len(S) + 1), S + " ") = 0 Then GoTo notthatone

addThisOne:
                'Console.WriteLine(S + " -> " + L)
                With ofMethod(SL.sourcePath)
                    detectMethRef.classPath = .patH
                    detectMethRef.isPublic = .isPublic
                    detectMethRef.varName = SL.searchStr
                End With
                'Console.WriteLine("MethRef identified - " + SL.searchStr)
            Else


                If isValidReference(classRefs, L, LCase(SL.searchStr)) = True Then
                    With ofMethod(SL.sourcePath)
                        detectMethRef.classPath = .patH
                        detectMethRef.isPublic = .isPublic
                        detectMethRef.varName = SL.searchStr
                    End With

                Else
                    'Console.WriteLine("Passing this up (was looking at " + S + ")" + vbCrLf + L)

                End If


            End If
notthatone:
        Next

checkMaybe:

foundIt:
    End Function

























    ' Class 2 of file - makeTMJson responsible for converting structure into ThreatModeler format
    ' Can also reduce scope by filtering out unspecified classes/methods and cutting off outbound connections of other components according to a depth

    Public Class makeTMJson
        '    "ObjectId":9,
        '        "ObjectType":"component",
        '        "ParentGroupId":2,
        '        "ComponentGuid":"F47FCE3A-C854-4A90-88C1-0D2C005BC511",
        '        "Name":"Akamai CDN",
        '        "OutBoundId":[10],
        '        "OutBoundGuids":["31D863C7-8E0B-49F2-9363-539ED8E97E72"]

        Public reportType As String
        Private bestMethod As String
        Private bestRMethod As String
        Private bestCC As String
        Private bestCL As String
        Private bestSF As String

        Public Class tmObject
            Public ObjectId As Integer
            Public ObjectType As String
            Public ParentGroupId As Integer
            Public ComponentGuid As String
            Public Name As String
            Public Notes As String
            Public OutBoundId As List(Of Integer)
            Public OutBoundGuids As List(Of String)

            Public Sub New()
                OutBoundId = New List(Of Integer)
                OutBoundGuids = New List(Of String)
            End Sub

        End Class
        Public Class guidList
            Public ListOfGuids As List(Of String)
            Public Sub New()
                ListOfGuids = New List(Of String)
            End Sub
        End Class

        Private Function getTmObject(objId As Integer, objType$, objName$, parentId As Integer, Optional ByVal doesReturn As Boolean = False, Optional Notes As String = "") As tmObject

            getTmObject = New tmObject
            With getTmObject
                .Name = objName
                .ObjectId = objId
                .ParentGroupId = parentId
                .Notes = Notes
                If LCase(objType) = "method" Then .ObjectType = "Component" Else .ObjectType = "Container"


                Select Case LCase(objType)
                    Case "method"
                        .ComponentGuid = bestMethod    ' "deba4981-1f92-4b3b-94c3-e603a660aff4"
                        If doesReturn Then .ComponentGuid = bestRMethod     ' "4d954e6e-ac82-4e67-ba28-78538a30fd48"
                    Case "class"
                        .ComponentGuid = bestCL     ' "cb374e7d-fdc5-4f0a-a164-a82e52a1a6ca"
                    Case "module"
                        .ComponentGuid = bestCC ' "9aec34ec-1715-431b-bc5e-e1ff40aa2b88"
                    Case "file"
                        .ComponentGuid = bestSF      ' "1c912bfb-cc5a-495d-84f3-79fdd2441132"
                        .Name = stripToFilename(.Name)
                End Select
            End With
        End Function

        Private Sub assignGuids(ByRef A As appScan)
            With A
                If .bestMethod = "" Then bestMethod = "deba4981-1f92-4b3b-94c3-e603a660aff4" Else bestMethod = .bestMethod
                If .bestRMethod = "" Then bestRMethod = "deba4981-1f92-4b3b-94c3-e603a660aff4" Else bestRMethod = .bestRMethod
                If .bestCC = "" Then bestCC = "deba4981-1f92-4b3b-94c3-e603a660aff4" Else bestCC = .bestCC
                If .bestCL = "" Then bestCL = "deba4981-1f92-4b3b-94c3-e603a660aff4" Else bestCL = .bestCL
                If .bestSF = "" Then bestSF = "deba4981-1f92-4b3b-94c3-e603a660aff4" Else bestSF = .bestSF
            End With
        End Sub

        Public Function getJSONobjects(ByRef A As appScan, Optional ByVal classesOnly As Boolean = False) As List(Of tmObject)
            ' bridge is either CREATE b2c9ccca-4c11-45ac-8b53-9a13577f2179
            ' or USE 3fa7bd26-7eb4-48c9-a6c5-b46b4a7e23cc
            ' or RETURN 6adacb2a-ae57-4efc-89ff-170d8fc5d5f1
            Call assignGuids(A)
            Dim allObjects As List(Of tmObject) = New List(Of tmObject)

            'For Each CC In A.sourceFiles
            '    allObjects.Add(getTmObject(CC.graphId, "file", stripToFilename(CC.fileName), 0))
            'Next
            Dim unqIDs As New Collection

            For Each CC2 In A.codeContainers
                If grpNDX(unqIDs, CC2.graphId) Then
                    Console.WriteLine("Duplicate at CC " + CC2.graphId.ToString)
                Else
                    unqIDs.Add(CC2.graphId)
                    Dim newGraphObj As New tmObject
                    newGraphObj = getTmObject(CC2.graphId, CC2.ccType, CC2.Name, A.findGraphId(CC2.ofParents))
                    If newGraphObj.ParentGroupId = -1 Then newGraphObj.ParentGroupId = 0 'this is a file, as graphID of parent is not found

                    'If onlyPublic Then
                    'If CC2.ccType = "Class" And CC2.isPublic = False Then GoTo skipMethods
                    'Including all classes.. will have to work out scope
                    'End If

                    Call addOutboundConnections(A, newGraphObj, CC2.usesMethods, "")
                    Call addOutboundConnections(A, newGraphObj, CC2.createsClasses, "")

                    allObjects.Add(newGraphObj)
                End If

                If classesOnly Then GoTo skipMethods

                For Each MM In CC2.allMethods

                    'If MM.isPublic = False And onlyPublic = True Then GoTo skipThisOne    'fix this

                    If grpNDX(unqIDs, MM.graphId) Then
                        'Console.WriteLine("Duplicate at " + MM.graphId.ToString)
                    Else
                        unqIDs.Add(MM.graphId)
                        Dim newGraphObj As New tmObject
                        Dim noteS$ = ""


                        If Len(MM.parametersExpected) Then
                            noteS += "PARAMETERS:" + vbCr + Replace(MM.parametersExpected, ",", vbCr)
                            noteS = Replace(noteS, "ByVal ", "")
                            noteS = Replace(noteS, "ByRef ", "")
                            noteS = Replace(noteS, " As ", "/")
                            noteS = Replace(noteS, "Optional", "")
                        End If
                        If Len(MM.returnType) Then noteS += vbCr + vbCr + "RETURNS:" + vbCr + MM.returnType

                        newGraphObj = getTmObject(MM.graphId, "method", MM.Name, A.findGraphId(MM.ofParent), MM.doesReturn, noteS)

                        Call addOutboundConnections(A, newGraphObj, MM.usesMethods, "")
                        Call addOutboundConnections(A, newGraphObj, MM.createsClasses, "")
                        Call addOutboundConnections(A, newGraphObj, MM.returnsTo, "")

                        allObjects.Add(newGraphObj)
                    End If
skipThisOne:
                Next
skipMethods:
            Next



            Return allObjects

            '                   Dim gId As Integer = 0
            '                   'add bridges
            '                   For Each P In CC2.usesMethods
            '                       gId = A.findGraphId(P)
            '                       If gId <> -1 Then
            '                           newGraphObj.OutBoundId.Add(gId)
            '                           newGraphObj.OutBoundGuids.Add("3fa7bd26-7eb4-48c9-a6c5-b46b4a7e23cc")
            '                       End If
            '                   Next
            '                   For Each P In CC2.createsClasses
            '                       'should have return for this!
            '                       gId = A.findGraphId(P)
            '                        If gId <> -1 Then
            '                            newGraphObj.OutBoundId.Add(gId)
            '                            newGraphObj.OutBoundGuids.Add("b2c9ccca-4c11-45ac-8b53-9a13577f2179")
            '                            ' for USE newGraphObj.OutBoundGuids.Add("3fa7bd26-7eb4-48c9-a6c5-b46b4a7e23cc")
            '                        End If
            '                    Next

            '                        Dim gID As Integer = 0
            '                        'add bridges
            '                        For Each P In MM.usesMethods
            '                            gID = A.findGraphId(P)
            '                            If gID <> -1 Then
            '                                newGraphObj.OutBoundId.Add(A.findGraphId(P))
            '                                newGraphObj.OutBoundGuids.Add("3fa7bd26-7eb4-48c9-a6c5-b46b4a7e23cc")
            '                            End If
            '                        Next
            '                        For Each P In MM.createsClasses
            '                            gID = A.findGraphId(P)
            '                            If gID <> -1 Then
            '                                newGraphObj.OutBoundId.Add(A.findGraphId(P))
            '                                newGraphObj.OutBoundGuids.Add("b2c9ccca-4c11-45ac-8b53-9a13577f2179")
            '                            End If
            '                            ' when using same newGraphObj.OutBoundGuids.Add("3fa7bd26-7eb4-48c9-a6c5-b46b4a7e23cc")
            '                        Next
            '                        For Each P In MM.returnsTo
            '                            gID = A.findGraphId(P)
            '                            If gID <> -1 Then
            '                                newGraphObj.OutBoundId.Add(A.findGraphId(P))
            '                                newGraphObj.OutBoundGuids.Add("6adacb2a-ae57-4efc-89ff-170d8fc5d5f1")
            '                            End If
            '                        Next

        End Function

        Private Sub addOutboundConnections(ByRef A As appScan, ByRef newGraphObj As tmObject, L As List(Of String), ByVal GUID As String)
            Dim gID As Integer = 0
            For Each P In L
                gID = A.findGraphId(P)
                If gID <> -1 Then
                    newGraphObj.OutBoundId.Add(A.findGraphId(P))
                    newGraphObj.OutBoundGuids.Add(GUID)
                End If
                ' when using same newGraphObj.OutBoundGuids.Add("3fa7bd26-7eb4-48c9-a6c5-b46b4a7e23cc")
            Next
        End Sub

        '            allFilteredObjects = buildSlices(allJsonObjects, classWatch, methodWatch)
        Public Function buildSlice(ByRef allObj As List(Of tmObject), chosenObjects As List(Of Integer), Optional ByVal maxDepth As Integer = 0, Optional ByVal showClients As Boolean = True) As List(Of tmObject)
            buildSlice = New List(Of tmObject)
            Dim newList As List(Of tmObject) = New List(Of tmObject)

            Dim toAdd As New List(Of tmObject)
            Dim chosenList As New List(Of tmObject)


            ' add codecontainers only if needed by an object making it to slice
            ' determine need by observing all method parents - if they do not exist, add to list

            For Each O In allObj
                If inIntList(chosenObjects, O.ObjectId) Then
                    chosenList.Add(O)
                End If
            Next

            For Each newO In chosenList
                newList.Add(newO)
            Next

            Console.WriteLine("# of Objects Directly Named: " + newList.Count.ToString)

skipInboundmap:


            ' GoTo skipOutboundmap
            'now add all objects called by any of the methods
            For Each adjO In newList
                For Each oID In adjO.OutBoundId
                    If existsAsObject(toAdd, oID) = False Then
                        'Console.WriteLine("Adding ID " + oID.ToString + " " + ofTMobj(allObj, oID).Name)
                        toAdd.Add(ofTMobj(allObj, oID))
                    End If
                Next
            Next

            For Each newO In toAdd
                If existsAsObject(newList, newO.ObjectId) = False Then newList.Add(newO)
            Next
            toAdd = New List(Of tmObject)

            Console.WriteLine("# with outbound adjacent Objects: " + newList.Count.ToString)
skipOutboundmap:

            If showClients = True Then

                'now add all objects calling existing methods
                toAdd = whoIsUsing(chosenList, allObj)

                For Each newO In toAdd
                    If existsAsObject(newList, newO.ObjectId) = False Then newList.Add(newO)
                Next
                toAdd = New List(Of tmObject)

                Console.WriteLine("# with inbound adjacent Objects: " + newList.Count.ToString)
                'GoTo skipOutboundmap
            End If


            'dont forget the parents
            Dim aPnum As Integer = 1
            Do Until aPnum = 0
                aPnum = addParents(allObj, newList)
            Loop

            Console.WriteLine("# with Parents: " + newList.Count.ToString)


            'Should now have all base objects chosen 
            Dim currDepth As Integer = 1
            Dim numAdded As Integer = 0


doItAgain:

            If maxDepth Then
                If currDepth >= maxDepth Then GoTo nextPhase
            End If

            currDepth += 1

            numAdded = resolveConnections(allObj, newList)

            Console.WriteLine("# with depth " + currDepth.ToString + ": " + newList.Count.ToString)

            'dont forget the parents
            aPnum = 1
            Do Until aPnum = 0
                aPnum = addParents(allObj, newList)
            Loop
            Console.WriteLine("       Plus with their parents: " + newList.Count.ToString)


            If numAdded Then GoTo doItAgain

nextPhase:
            ' now go through all objects and delete outboundIDs and GUIDs of objects at the edge of scope
            'Console.WriteLine("Current Depth " + currDepth.ToString + ": " + buildSlice.Count.ToString + " objects in slice")

            'now remove outbound connections to items that don't exist

            For Each obJ In newList
                If obJ.OutBoundId.Count = 0 Then GoTo none2remove
                'Console.WriteLine("Checking " + obJ.ObjectId.ToString + ":" + obJ.Name + "/" + obJ.OutBoundId.Count.ToString + " connections")
                Dim K As Integer = 0
                For K = obJ.OutBoundId.Count - 1 To 0 Step -1
                    If existsAsObject(newList, obJ.OutBoundId(K)) = False Then
                        'Console.WriteLine((K + 1).ToString + "/" + obJ.OutBoundId.Count.ToString + " - REMOVING ID " + obJ.OutBoundId(K).ToString + " - NOT FOUND in current slice")
                        obJ.OutBoundId.RemoveAt(K)
                        obJ.OutBoundGuids.RemoveAt(K)
                        'Else
                        '   Console.WriteLine((K + 1).ToString + "/" + obJ.OutBoundId.Count.ToString + " - " + obJ.OutBoundId(K).ToString + " is ID of " + ofTMobj(newList, obJ.OutBoundId(K)).Name)
                    End If
                Next
none2remove:
            Next

            Return newList
        End Function

        Private Function addParents(ByRef allObj As List(Of tmObject), ByRef currSlice As List(Of tmObject)) As Integer
            addParents = 0

            Dim toAdd As List(Of tmObject) = New List(Of tmObject)

            For Each O In currSlice
                If O.ParentGroupId = 0 Then GoTo nextOne ' this is part of base
                If ofTMobj(currSlice, O.ParentGroupId).ObjectId = 0 Then
                    ' parent does not exist
                    If ofTMobj(toAdd, O.ParentGroupId).ObjectId = 0 Then
                        toAdd.Add(ofTMobj(allObj, O.ParentGroupId))
                        addParents += 1
                    End If
                End If
nextOne:
            Next

            For Each T In toAdd
                'Console.WriteLine(T.ObjectId.ToString + " - " + T.Name)
                currSlice.Add(T)
            Next

        End Function

        Private Function existsAsObject(ByRef L As List(Of tmObject), objID As Integer) As Boolean
            existsAsObject = False

            If ofTMobj(L, objID).ObjectId Then existsAsObject = True
            ' Console.WriteLine(CStr(existsAsObject))
        End Function
        Private Function whoIsUsing(ByRef sourceList As List(Of tmObject), ByRef crowdList As List(Of tmObject)) As List(Of tmObject)
            whoIsUsing = New List(Of tmObject)

            Dim isNeighbor As Boolean

            For Each S In sourceList
                For Each C In crowdList
                    isNeighbor = False
                    For Each oID In C.OutBoundId
                        If oID = S.ObjectId Then isNeighbor = True
                    Next
                    If isNeighbor = True Then
                        If existsAsObject(sourceList, C.ObjectId) = False Then
                            If existsAsObject(whoIsUsing, C.ObjectId) = False Then
                                whoIsUsing.Add(C)
                            End If
                        End If
                    End If
                Next
            Next

        End Function

        Private Function resolveConnections(ByRef allObj As List(Of tmObject), ByRef currSlice As List(Of tmObject)) As Integer
            ' returns number of objects added to slice
            resolveConnections = 0
            Dim toAdd As List(Of tmObject) = New List(Of tmObject)

            ' don't do this.. brings in everything
            ' toAdd = New List(Of tmObject)
            ' toAdd = whoIsUsing(currSlice, allObj)
            ' For Each obJ In toAdd
            '     'Console.WriteLine(obJ.ObjectId.ToString + " - " + obJ.Name)
            '     currSlice.Add(obJ)
            ' Next
            ' toAdd = New List(Of tmObject)

            For Each O In currSlice
                If O.OutBoundId.Count Then
                    Dim K As Integer
                    For K = 0 To O.OutBoundId.Count - 1
                        'Console.WriteLine("Evaluating currslice " + O.ObjectId.ToString + " - " + O.Name + " connection to " + O.OutBoundId(K).ToString)
                        If ofTMobj(currSlice, O.OutBoundId(K)).ObjectId = 0 Then
                            ' outbound connection does not exist.. add node
                            If existsAsObject(toAdd, O.OutBoundId(K)) = False Then ' ofTMobj(toAdd, O.OutBoundId(K)).ObjectId = 0 Then
                                resolveConnections += 1
                                toAdd.Add(ofTMobj(allObj, O.OutBoundId(K))) ' 
                                'Console.WriteLine("Added " + ofTMobj(allObj, O.OutBoundId(K)).ObjectId.ToString + " - " + ofTMobj(allObj, O.OutBoundId(K)).Name)
                            End If
                        End If
                    Next
                End If
            Next

            For Each obJ In toAdd
                'Console.WriteLine(obJ.ObjectId.ToString + " - " + obJ.Name)
                currSlice.Add(obJ)
            Next


        End Function

        Private Function ofTMobj(ByRef allObj As List(Of tmObject), ByVal ObjId As Integer) As tmObject
            ofTMobj = New tmObject

            For Each C In allObj
                If C.ObjectId = ObjId Then
                    Return C
                End If
            Next
        End Function
    End Class

End Class

