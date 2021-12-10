// 외부 모듈
var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var bodyParser = require('body-parser');
var crypto = require('crypto');
var newDate = require('date-utils');
var session = require('express-session');
//var MySQLStore = require('express-mysql-session')(session);
var FileStore = require('session-file-store')(session);
var cors = require('cors');
var logger = require('morgan');
var fs = require('fs');
var mysql = require('mysql');
var multer = require('multer');
var path = require('path');
var static = require('serve-static');
var mime = require('mime');
var CryptoJS = require('crypto-js');
var exec = require('child_process').execFile;
const encrypt = require('node-file-encrypt');
const nodemailer = require('nodemailer');

// **************** MySQL 데이터베이스 연결 ******************
try{
  var client = mysql.createConnection({  // 로컬 mysql의 ebs 데이터베이스 연결
    host: 'localhost',
    port: 3306,
    user: 'root',
    password: '123456',
    database: 'ebs',
    dateStrings: 'date'
  });
} catch(e){  // 오류 알림
  console.log(e.name);
  console.log(e.message);
}
client.connect((err) => {
  if(err) {
    throw err;
  }else{
  logging('DBMS Connected !!');
}
  // user/post 테이블 없으면 생성 코드 차후 추가
});

// **************** 사용자 함수 선언 ******************
function encryptionPW(pw) { // 비밀번호 암호화를 위한 함수
  var encrypted = crypto.createHash('sha512').update(pw).digest('base64');
  encrypted = encrypted.substring(0, 9)
  return encrypted;
}

function now() {  // 지금 시간 추출 함수
  var currentdate = new Date();
  var now = currentdate.toFormat('YYYY-MM-DD HH24:MI:SS');
  return now;
}

function logging(logstr){  // app.log에 log를 찍기 위한 함수
  fs.appendFile('app.log', logstr + '\n', 'UTF8', function(err){
    if(err) throw err;
    console.log(logstr);
  });
}

// 서버 생성
var app = express();
var router = express.Router();
// 서버 환경 설정
app.settings.env = 'production';

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs'); // ejs 사용
app.engine('html', require('ejs').renderFile);

// 미들웨어 설정
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '/')));
app.use('/files', static(path.join(__dirname, 'files')));  // 파일 저장 경로 기본 설정
app.use(bodyParser.urlencoded({extended: false}));
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(session({  // 세션 설정
  key: 'loginData',
  secret: 'secret',
  resave: false,
  saveUninitialized: true,
  cookie: {
    // maxAge: 1000 * 60 * 2
  },
  rolling: true,
  store: new FileStore()
}));

// 파일 암호화 키 (하드코딩)
let passwordkey = require("./enc.js");  // 암호화 되어있는 키가 적혀있는 경로
passwordkey = String(Object.values(passwordkey)).substring(7, 50);  // 더미 코드 제거하고 문자열 변환
let key = CryptoJS.AES.decrypt(passwordkey,"key").toString(CryptoJS.enc.Utf8);  // 복호화하여 키로 만듦

// 파일 경로 저장
var storage = multer.diskStorage({  // 파일 경로 및 이름 저장
    destination: function (req, file, cb){
      cb(null, 'files/');
    },
    filename: function (req, file, cb){
        cb(null, Date.now() + '-' + file.originalname)
    }
});

var upload = multer({
  storage: storage
});

// 이메일 전송하여 랜덤 비밀번호 부여받을 때 사용되는 코드
var variable = "0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z".split(",");  // 문자열 랜덤으로 뽑기위한

function createRandomPassword(variable, passwordLength){  // 랜덤 비밀번호 생성하는 함수
  var randomString = "";
  for(var j=0; j<passwordLength; j++){
    randomString += variable[Math.floor(Math.random() * variable.length)];
  }
  return randomString;
}

// 임시 비밀번호 메일 보내기
var transporter = nodemailer.createTransport({
  service: 'gmail',
  port: 465,
  secure: true,
  auth: {
    user: 'ebsbidding@gmail.com',
    pass: 'ebs0207!!'
  },
});




// **************** 라우터 코드 ******************
// 홈페이지
app.get('/', function(req, res, next){
  res.redirect('/home');
  logging(now() + ' : 홈 페이지에 접속하였습니다!');
});

app.get('/home', function(req, res, next){
  var sql = 'SELECT * FROM post ORDER BY date DESC';

  client.query(sql, (err, result, fields) => {  // 메인화면에 최근 공고 출력
    if(err){
      logging(sql);
      logging(now() + ' : DB 오류 발생.');
      res.send("<script>alert('오류');location.href='/home';</script>");
    } else{
      res.render('home.ejs', {
        result: result
      });
      logging(now() + ' : 홈 페이지에 접속하였습니다!');
    }
  });
});

// 공지사항
app.get('/notice', function(req, res, next){
  res.render('notice.ejs');
  logging(now() + ' : 공지사항 페이지에 접속하였습니다.');
});

// Q&A
app.get('/Q&A', function(req, res, next){
  res.render('Q&A.ejs');
  logging(now() + ' : 질문 페이지에 접속하였습니다.');
});

// 입찰 공고 목록
app.get('/posting', function(req, res, next){
  var order = ' ORDER BY';
  var day = ' date';
  var dead = ' deadline';
  var latest = ' ASC';
  var recent = ' DESC';

  var sql = 'SELECT * FROM post WHERE date < now()';
  var searchquery = 'SELECT * FROM post WHERE date < now() AND (title LIKE ? OR content LIKE ?)';

  if(req.query.category == 'stuff'){  // 분야로 검색
    searchquery = searchquery + " AND category='물품'";
    sql = sql + " AND category='물품'";
  } else if (req.query.category == 'work') {
    searchquery = searchquery + " AND category='공사'";
    sql = sql + " AND category='공사'";
  } else if (req.query.category == 'service') {
    searchquery = searchquery + " AND category='용역'";
    sql = sql + " AND category='용역'";
  } else if (req.query.category == 'foreign') {
    searchquery = searchquery + " AND category='외자'";
    sql = sql + " AND category='외자'";
  } else if (req.query.category == 'reserve') {
    searchquery = searchquery + " AND category='비축'";
    sql = sql + " AND category='비축'";
  } else if (req.query.category == 'etc') {
    searchquery = searchquery + " AND category='기타'";
    sql = sql + " AND category='기타'";
  }

  if(req.query.dead){  // 제거할 공고 선택
    searchquery = searchquery + " AND deadline > now()";
    sql = sql + " AND deadline > now()";
  }
  if(req.query.almost_dead){
    searchquery = searchquery + " AND deadline > date_add(now(), interval 7 day)";
    sql = sql + " AND deadline > date_add(now(), interval 7 day)";
  }
  if(req.query.old){
    searchquery = searchquery + " AND date > date_sub(now(), interval 3 day)";
    sql = sql + " AND date > date_sub(now(), interval 3 day)";
  }
  if(req.query.overlap){
    searchquery = searchquery + " GROUP BY title";
    sql = sql + " GROUP BY title";
  }

  if(req.query.day == 'day_recent'){  // 정렬 방식 선택
    searchquery = searchquery + order + day + recent;
    sql = sql + order + day + recent;
  } else if (req.query.day == 'dead_latest') {
    searchquery = searchquery + order + dead + recent;
    sql = sql + order + dead + recent;
  } else if (req.query.day == 'dead_recent') {
    searchquery = searchquery + order + dead + latest;
    sql = sql + order + dead + latest;
  } else if(req.query.day == 'day_latest'){
    searchquery = searchquery + order + day + latest;
    sql = sql + order + day + latest;
  } else{
    searchquery = searchquery + order + day + recent;
    sql = sql + order + day + recent;
  }

  if(req.query.searchb){  // 검색어를 입력한 경우 검색 쿼리
    var search = req.query.searchb;
    logging(searchquery);
    client.query(searchquery, ['%'+search+'%', '%'+search+'%'], function(err, results){
      if(err){
        logging(now() + ' : DB 오류 발생.');
        res.send("<script>alert('오류');location.href='/home';</script>");
      } else{
        res.render('posting.ejs', {
          result: results
        });
      }
    });
  } else{  // 검색어를 입력하지 않은 경우 검색 쿼리
    client.query(sql, (err, result, fields) => {
      if(err){
        logging(sql);
        logging(now() + ' : DB 오류 발생.');
        res.send("<script>alert('오류');location.href='/home';</script>");
      } else{
        res.render('posting.ejs', {
          result: result
        });
        logging(now() + ' : 입찰공고 페이지에 접속하였습니다.');
      }
    });
  }
});

// 공고 열람
app.get('/post/:id', function(req, res, next){  // 공고마다 지정된 일련번호(기본키) == id
  var id = req.params.id;

  var sqlcount = 'UPDATE post SET count=count+1 where id=?';
  client.query(sqlcount, [id], function(err, result){  // 한 번 공고 열람 시마다 열람 횟수 +1
    if(err){
      logging(now() + ' : 글 렌더링 오류!');
      res.send("<script>alert('오류');location.href='/home';</script>");
    }else{
      var sql = 'SELECT id, auth, date, title, content, category, count, file, deadline, re_bid from post where id=?';
      client.query(sql, [id], function(err, row){  // 공고 열람
        f = row[0].file;  // 파일 다운로드 설정을 위한 이름 변경
        fi = f.split('\\');
        console.log(fi);
        fil = fi[1];
        console.log(fil);
        file = fil.split('.');
        res.render('post', {title: '글 상세', row: row[0], file: file[0]});
      });
    }
  });
});

// 파일 다운로드
app.get('/download/:id/:file_name', function(req, res, next) {
  let decrfilePath = 'decFiles/'; // 복호화 파일 저장 경로
  var post_id = req.params.id;
  var sql = 'SELECT * FROM post WHERE id=?';
  client.query(sql, [post_id], function(err, result){  // 해당 공고에서 파일경로와 포맷 추출
    if(err){
      console.log('오류');
    } else{
      var meme = result[0].filememe;
      let decrPathNfile = decrfilePath + req.params.file_name + meme;  // 복호화 파일 경로+파일명 저장용
      let encrPathNfile = 'encFiles/' + req.params.file_name + '.crypt';
      var decfile = decrPathNfile;
      var files = decrPathNfile;

      if (fs.existsSync(decrPathNfile)) {  // 복호화 파일이 있으면 에러발생, 검사-삭제후 실행코드 필요!!
         fs.unlink(decrPathNfile, function() {}); // 복호화 파일 존재시 삭제
      }
      let f = new encrypt.FileEncrypt(encrPathNfile, decrfilePath);  // encryptPathNfile = 암호화된 새 파일명(경로포함), 서로 다른 프로그램에서 호출시 encryptPathNfile를 넘겨줄 것
      f.openSourceFile();
      decrPathNfile = f.decrypt(key);    // 암호화 키로 파일 복호화 , 파일명까지 원상복구 시킴

      var upload_folder = 'decFiles/';
      var file = decfile; // ex) /upload/files/sample.txt

      try {
        if (fs.existsSync(file)) { // 파일이 존재하는지 체크
          var filename = path.basename(file); // 파일 경로에서 파일명(확장자포함)만 추출
          var mimetype = mime.lookup(file); // 파일의 타입(형식)을 가져옴

          res.setHeader('Content-disposition', 'attachment; filename=' + filename); // 다운받아질 파일명 설정
          res.setHeader('Content-type', mimetype); // 파일 형식 지정

          var filestream = fs.createReadStream(file);
          filestream.pipe(res);  // 바로 다운로드
        } else {
          res.send('해당 파일이 없습니다.');
          return;
        }
        if (fs.existsSync(files)) {  // 이미 복호화 파일 존재 시
           console.log("기존 복호화 파일 삭제");
           fs.unlink(files, function() {}); // 해당 파일 삭제
        }
      } catch (e) { // 에러 발생시
        console.log(e);
        res.send('파일을 다운로드하는 중에 에러가 발생하였습니다.');
        return;
      }
    }
  });
});

// 입찰 지원 목록의 파일 다운로드
app.get('/biddownload/:id/:file_name', function(req, res, next) {
  let decrfilePath = 'decFiles/'; // 복호화 파일 저장 경로
  var post_id = req.params.id;
  var sql = 'SELECT * FROM bidding WHERE id=?';
  client.query(sql, [post_id], function(err, result){
    if(err){
      console.log('오류');
    } else{
      var meme = result[0].bid_filememe;
      let decrPathNfile = decrfilePath + req.params.file_name + meme;  // 복호화 파일 경로+파일명 저장용
      let encrPathNfile = 'encFiles/' + req.params.file_name + '.crypt';
      console.log("복호화폴더: ", decrfilePath);
      console.log("복호화파일: ", decrPathNfile);
      console.log("암호화파일: ", encrPathNfile);
      var decfile = decrPathNfile;
      var files = decrPathNfile;

      if (fs.existsSync(decrPathNfile)) {  // 복호화 파일이 있으면 에러발생, 검사-삭제후 실행코드 필요!!
         fs.unlink(decrPathNfile, function() {}); // 복호화 파일 존재시 삭제
         console.log("기존 복호화 파일 삭제");
      }
      let f = new encrypt.FileEncrypt(encrPathNfile, decrfilePath);  // encryptPathNfile = 암호화된 새 파일명(경로포함), 서로 다른 프로그램에서 호출시 encryptPathNfile를 넘겨줄 것
      f.openSourceFile();
      decrPathNfile = f.decrypt(key);    // 암호화 키로 파일 복호화 , 파일명까지 원상복구 시킴
      console.log("decrypt sync done");

      var upload_folder = 'decFiles/';
      var file = decfile; // ex) /upload/files/sample.txt

      try {
        if (fs.existsSync(file)) { // 파일이 존재하는지 체크
          var filename = path.basename(file); // 파일 경로에서 파일명(확장자포함)만 추출
          var mimetype = mime.lookup(file); // 파일의 타입(형식)을 가져옴

          res.setHeader('Content-disposition', 'attachment; filename=' + filename); // 다운받아질 파일명 설정
          res.setHeader('Content-type', mimetype); // 파일 형식 지정

          var filestream = fs.createReadStream(file);
          filestream.pipe(res);
        } else {
          res.send('해당 파일이 없습니다.');
          return;
        }
        if (fs.existsSync(files)) {
           console.log("기존 복호화 파일 삭제");
           fs.unlink(files, function() {}); // 복호화 파일 존재시 삭제
        }
      } catch (e) { // 에러 발생시
        console.log(e);
        res.send('파일을 다운로드하는 중에 에러가 발생하였습니다.');
        return;
      }
    }
  });
});

// 문의 게시글의 파일 다운로드
app.get('/askdownload/:id/:file_name', function(req, res, next) {
  let decrfilePath = 'decFiles/'; // 복호화 파일 저장 경로
  var post_id = req.params.id;
  var sql = 'SELECT * FROM ask WHERE ask_id=?';
  client.query(sql, [post_id], function(err, result){
    if(err){
      console.log('오류');
    } else{
      var meme = result[0].ask_askfilememe;
      let decrPathNfile = decrfilePath + req.params.file_name + meme;  // 복호화 파일 경로+파일명 저장용
      let encrPathNfile = 'encFiles/' + req.params.file_name + '.crypt';
      console.log("복호화폴더: ", decrfilePath);
      console.log("복호화파일: ", decrPathNfile);
      console.log("암호화파일: ", encrPathNfile);
      var decfile = decrPathNfile;
      var files = decrPathNfile;

      if (fs.existsSync(decrPathNfile)) {  // 복호화 파일이 있으면 에러발생, 검사-삭제후 실행코드 필요!!
         fs.unlink(decrPathNfile, function() {}); // 복호화 파일 존재시 삭제
         console.log("기존 복호화 파일 삭제");
      }
      let f = new encrypt.FileEncrypt(encrPathNfile, decrfilePath);  // encryptPathNfile = 암호화된 새 파일명(경로포함), 서로 다른 프로그램에서 호출시 encryptPathNfile를 넘겨줄 것
      f.openSourceFile();
      decrPathNfile = f.decrypt(key);    // 암호화 키로 파일 복호화 , 파일명까지 원상복구 시킴
      console.log("decrypt sync done");

      var upload_folder = 'decFiles/';
      var file = decfile; // ex) /upload/files/sample.txt

      try {
        if (fs.existsSync(file)) { // 파일이 존재하는지 체크
          var filename = path.basename(file); // 파일 경로에서 파일명(확장자포함)만 추출
          var mimetype = mime.lookup(file); // 파일의 타입(형식)을 가져옴

          res.setHeader('Content-disposition', 'attachment; filename=' + filename); // 다운받아질 파일명 설정
          res.setHeader('Content-type', mimetype); // 파일 형식 지정

          var filestream = fs.createReadStream(file);
          filestream.pipe(res);
        } else {
          res.send('해당 파일이 없습니다.');
          return;
        }
        if (fs.existsSync(files)) {
           console.log("기존 복호화 파일 삭제");
           fs.unlink(files, function() {}); // 복호화 파일 존재시 삭제
        }
      } catch (e) { // 에러 발생시
        console.log(e);
        res.send('파일을 다운로드하는 중에 에러가 발생하였습니다.');
        return;
      }
    }
  });
});

// 문의 답변 게시글의 파일 다운로드
app.get('/answerdownload/:id/:file_name', function(req, res, next) {
  let decrfilePath = 'decFiles/'; // 복호화 파일 저장 경로
  var post_id = req.params.id;
  var sql = 'SELECT * FROM ask WHERE ask_id=?';
  client.query(sql, [post_id], function(err, result){
    if(err){
      console.log('오류');
    } else{
      var meme = result[0].ask_answerfilememe;
      let decrPathNfile = decrfilePath + req.params.file_name + meme;  // 복호화 파일 경로+파일명 저장용
      let encrPathNfile = 'encFiles/' + req.params.file_name + '.crypt';
      console.log("복호화폴더: ", decrfilePath);
      console.log("복호화파일: ", decrPathNfile);
      console.log("암호화파일: ", encrPathNfile);
      var decfile = decrPathNfile;
      var files = decrPathNfile;

      if (fs.existsSync(decrPathNfile)) {  // 복호화 파일이 있으면 에러발생, 검사-삭제후 실행코드 필요!!
         fs.unlink(decrPathNfile, function() {}); // 복호화 파일 존재시 삭제
         console.log("기존 복호화 파일 삭제");
      }
      let f = new encrypt.FileEncrypt(encrPathNfile, decrfilePath);  // encryptPathNfile = 암호화된 새 파일명(경로포함), 서로 다른 프로그램에서 호출시 encryptPathNfile를 넘겨줄 것
      f.openSourceFile();
      decrPathNfile = f.decrypt(key);    // 암호화 키로 파일 복호화 , 파일명까지 원상복구 시킴
      console.log("decrypt sync done");

      var upload_folder = 'decFiles/';
      var file = decfile; // ex) /upload/files/sample.txt

      try {
        if (fs.existsSync(file)) { // 파일이 존재하는지 체크
          var filename = path.basename(file); // 파일 경로에서 파일명(확장자포함)만 추출
          var mimetype = mime.lookup(file); // 파일의 타입(형식)을 가져옴

          res.setHeader('Content-disposition', 'attachment; filename=' + filename); // 다운받아질 파일명 설정
          res.setHeader('Content-type', mimetype); // 파일 형식 지정

          var filestream = fs.createReadStream(file);
          filestream.pipe(res);
        } else {
          res.send('해당 파일이 없습니다.');
          return;
        }
        if (fs.existsSync(files)) {
           console.log("기존 복호화 파일 삭제");
           fs.unlink(files, function() {}); // 복호화 파일 존재시 삭제
        }
      } catch (e) { // 에러 발생시
        console.log(e);
        res.send('파일을 다운로드하는 중에 에러가 발생하였습니다.');
        return;
      }
    }
  });
});

// 공고 작성 화면
app.get('/postW', function(req, res, next){
  if(req.session.loggedin == true){
    res.render('postW.ejs');
    logging(now() + ' : 공고 작성 페이지에 접속하였습니다.');
  } else{
    logging(now() + ' : 허가받지 않은 사용자가 공고 작성 페이지에 접속하였습니다.');
    res.send("<script>alert('로그인이 필요합니다!');location.href='/login';</script>");
  }
});

app.post('/postW/write', upload.single('file'), (req, res)=>{

  var title = req.body.title;
  var category = req.body.category;
  var content = req.body.content;
  var file = `/files/${req.file.filename}`;
  var deadline = req.body.date + ' ' + req.body.time+':00';

  let orgFilename  = req.file.filename;
  let extension    = orgFilename.substr(-4, 4);  // 파일 확장자 ==> txt, jpg, png, mp4 암호화 및 복호화 OK
  let filename     = orgFilename.replace(extension, '');  // 원본 파일
  let orgfilePath  = 'files/';    // 원본 파일 경로
  let encrfilePath = 'encFiles/'; // 암호화 파일 저장 경로
  let decrfilePath = 'decFiles/'; // 복호화 파일 저장 경로

  let orgPathNfile = orgfilePath  + orgFilename;  // 원본 파일 경로+파일명
  let encrPathNfile= encrfilePath + filename + '.crypt'; // 암호화 파일 경로+파일명 저장용

  console.log("원 본 폴더: ", orgfilePath);
  console.log("원 본 파일: ", orgPathNfile);
  console.log("암호화폴더: ", encrfilePath);
  console.log("암호화파일: ", encrPathNfile);

  // 암호화 저장
  if (fs.existsSync(encrPathNfile)) {  // 암호화 키로 파일 암호화, 암호화 파일이 있으면 에러발생, 검사-삭제후 실행코드 필요!!
     console.log("기존 암호화 파일 삭제 ");
     fs.unlink(encrPathNfile, function() {}); // 암호화 파일 존재시 삭제
  }
  let f = new encrypt.FileEncrypt(orgPathNfile, encrfilePath, '.crypt', false); // false=파일명 변경 안함, true=무작위 파일명 생성
  f.openSourceFile();
  f.encrypt(key);
  encrPathNfile = f.encryptFilePath;  // 암호화된 새 파일명(경로포함) 저장
  console.log("encrypt sync done");

  fs.unlink(orgPathNfile, function() {}); // 암호화 전 파일 삭제

  if(deadline < now()){
    logging(now() + ' : 날짜 입력 오류!');
    res.send("<script>alert('잘못된 개찰일 설정입니다.');location.href='/postW';</script>");
  }else{
    var datas = [req.session.name, now(), title, content, category, encrPathNfile, deadline, extension];
    var sql = 'INSERT INTO post(auth, date, title, content, category, count, file, deadline, filememe) VALUES(?, ?, ?, ?, ?, 0, ?, ?, ?)';
    client.query(sql, datas, function(err, result){
      if(err){
        logging(now() + ' : 공고 작성 DB 오류!');
        res.send("<script>alert('오류');location.href='/postW';</script>");
      } else{
        res.redirect('/posting');
      }
    });
  }
});

// 로그아웃
app.get('/logout', function(request, response, next){
  request.session.loggedin = false;
  logging(now() + ' : 로그아웃!');
  response.send("<script>alert('성공적으로 로그아웃 되었습니다.');location.href='/home';</script>");
});

// 로그인
app.get('/login', function(req, res, next){
  res.render('login.ejs');
  logging(now() +  ' : ' +req.session.loggedin);
  logging(now() + ' : 로그인 페이지에 접속하였습니다.');
});

app.post('/login', function(request, response){
  var id = request.body.id;
  var pd = request.body.pw;

  // 사용자 id가 존재하는지 확인
  var sql = 'SELECT * FROM user WHERE user_id = ?';
  client.query(sql, [id], (err, data) => {

    if (err) {
      logging(now() + ' : 로그인 오류 발생.');
      response.send("<script>alert('오류');location.href='/login';</script>");
    }

    // 동일한 id가 있는지 확인
    else if (data.length === 0) {
      logging(now() + ' : ID가 다릅니다. 로그인 실패!');
      response.send("<script>alert('ID 혹은 암호가 다릅니다!');location.href='/login';</script>");
    }else{
      var idnum = data[0].id;
      var id = data[0].user_id;
      var name = data[0].name;
      var prov = data[0].provider;
      var date = data[0].created_at;

      // 패스워드 암호화
      var encryption = encryptionPW(pd)
      // var encryption = pd
      // 패스워드 일치 여부 확인
      sql = 'SELECT STRCMP(?, ?) AS COMPARE';
      var pwCompare = [encryption, data[0].password]
      client.query(sql, pwCompare, function (err, result, fields) {
        if (err) {
          logging(now() + ' : 로그인 오류 발생.');
          response.send("<script>alert('오류');location.href='/login';</script>");
        }

        // 패스워드가 불일치 한다면 실패
        else if (result[0].COMPARE !== 0) {
          logging(now() + ' : 암호가 다릅니다. 로그인 실패!');
          response.send("<script>alert('ID 혹은 암호가 다릅니다!');location.href='/login';</script>");
        } else{
          // 패스워드 일치 성공 시 세션에 로그인 성공 저장
            logging(now() + ' : 로그인 하였습니다!');
            request.session.loggedin = true;
            request.session.idnum = idnum;
            request.session.userid = id;
            request.session.name = name;
            request.session.prov = prov;
            request.session.date = date;
            response.send("<script>alert('로그인 하였습니다!');location.href='/home';</script>");
          }
        });
      }
    });
});

// 회원가입
app.get('/signUp', function(req, res, next){
  res.render('signUp.ejs');
  logging(now() + ' : 회원가입 페이지에 접속하였습니다.');
});

app.post('/signup', function(request, response){
  var id = request.body.id;
  var pd = request.body.pw;
  var pwre = request.body.pwre;
  var name = request.body.name;
  var provider = request.body.provider;
  var ch = request.body.ch;
  var p1 = request.body.txtMobile1;
  var p2 = request.body.txtMobile2;
  var p3 = request.body.txtMobile3;
  var phone = p1 +'-'+ p2 +'-'+ p3;
  logging(phone);
  var time = now();
  var email = request.body.email;

  // user테이블에 해당 user_ID가 이미 있는지 확인하는 쿼리
  var idcheck = 'SELECT * FROM user WHERE user_id = ?';
  var namecheck = 'SELECT * FROM user WHERE name = ?';

  // 입력이 다 되어있는지 확인
  if(!id || !pd || !pwre || !name || !provider || !ch || !phone || !email){
    logging(provider);
    logging(now() + ' : 데이터 입력 값 부족으로 회원가입 실패!');
    response.send("<script>alert('값을 전부 입력해주세요.');location.href='/signup';</script>");
  } else if (pd != pwre) { // 암호와 암호 확인이 같은지 확인
    logging(now() + ' : 비밀번호 확인이 틀려 회원가입 실패!');
    response.send("<script>alert('비밀번호와 비밀번호 확인이 다릅니다.');location.href='/signup';</script>");
  } else { // 위 다 만족하면 DB 확인 진행
    client.query(idcheck, [id], (err, results, fields) => {
      if(err){
        logging(now() + ' : 회원가입 DB 오류! 1' + err);
        response.send("<script>alert('오류');location.href='/signup';</script>");
      } else if(results.length >= 1){ // 이미 같은 id로 회원이 존재한다면
        logging(now() + ' : 중복 ID로 회원가입 시도하여 실패!');
        response.send("<script>alert('이미 같은 ID가 존재합니다!');location.href='/signup';</script>");
      } else { // 회원가입 시작
        client.query(namecheck, [name], (err, data, fields) => {
          if(err){
            logging(now() + ' : 회원가입 DB 오류! 3' + err);
            response.send("<script>alert('오류');location.href='/signup';</script>");
          } else if(data.length >= 1){
            logging(now() + ' : 중복 이름으로 회원가입 시도하여 실패!');
            response.send("<script>alert('이미 같은 이름이 존재합니다!');location.href='/signup';</script>");
          } else{
            if (provider == "buyer") {  // 체크에 따라 구매자/공급자
              provider = 0;
              logging(provider);
            } else{
              provider = 1;
              logging(provider);
            }
            // 보안을 위해 패스워드 암호화
            var encryption = encryptionPW(pd)
            // 아이디와 암호화 한 패스워드를 DB에 저장
            signupsql = 'INSERT INTO user (user_id, password, name, provider, created_at, phone_num, ask_time, answer_time, email) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
            client.query(signupsql, [id, encryption, name, provider, time, phone, now(), now(), email], function(err, result, fields){
              if (err){
                logging(now() + ' : 회원가입 DB 오류! 2');
                response.send("<script>alert('오류');location.href='/signup';</script>");
              } else{
                logging(now() + ' : 회원가입 성공!');
                response.send("<script>alert('회원가입에 성공하였습니다! 로그인해주세요.');location.href='/login';</script>");
              }
            });
          }
        });
      }
    });
  }
});

// 마이페이지
app.get('/mypage', function(req, res, next){
  var order = ' ORDER BY';
  var day = ' date';
  var dead = ' deadline';
  var latest = ' ASC';
  var recent = ' DESC';

  var sql = 'SELECT * FROM post WHERE auth=?';  // 해당 계정이 작성한 공고 목록

  if(req.query.day == 'day_recent'){  // 정렬 방식 선택
    sql = sql + order + day + recent;
  } else if (req.query.day == 'dead_recent') {
    sql = sql + order + dead + recent;
  } else if (req.query.day == 'dead_latest') {
    sql = sql + order + dead + latest;
  } else if(req.query.day == 'day_latest'){
    sql = sql + order + day + latest;
  } else{
    sql = sql + order + day + recent;
  }

  var newsql = 'SELECT * FROM user WHERE user_id=?';
  var asksql = 'SELECT ask_date FROM ask WHERE ask_postauth=? ORDER BY ask_date DESC';
  var answersql = 'SELECT ask_answertime FROM ask WHERE ask_auth=? ORDER BY ask_answertime DESC';

  if(req.session.loggedin == true){
    client.query(sql, [req.session.name], function(err, result){
      client.query(newsql, [req.session.userid], function(err, results){
        client.query(asksql, [req.session.name], function(err, asknew){
          if(err){

          } else{
            client.query(answersql, [req.session.name], function(err, answernew){
              if(err){
                logging(now() + "마이페이지 개인 정보 열람 오류");
              } else{
                if(asknew[0]){
                  if(req.session.prov == 0){  // 구매자인지 공급자인지 표시
                    var prov = "구매자";
                  } else{
                    var prov = "공급자";
                  }
                  if(answernew[0]){  // 질문 및 답변이 존재하는지에 따라 렌더링
                    res.render('mypage.ejs',{
                      user_id: req.session.userid,
                      name: req.session.name,
                      provider: prov,
                      created_at: req.session.date,
                      result: result,
                      userask: results[0].ask_time,
                      useranswer: results[0].answer_time,
                      ask: asknew[0].ask_date,
                      answer: answernew[0].ask_answertime
                    });
                  }else{
                    logging(2);
                    res.render('mypage.ejs',{
                      user_id: req.session.userid,
                      name: req.session.name,
                      provider: prov,
                      created_at: req.session.date,
                      result: result,
                      userask: results[0].ask_time,
                      useranswer: results[0].answer_time,
                      ask: asknew[0].ask_date,
                      answer: 0
                    });
                  }
                } else{
                  if(answernew[0]){
                    logging(3);
                    res.render('mypage.ejs',{
                      user_id: req.session.userid,
                      name: req.session.name,
                      provider: prov,
                      created_at: req.session.date,
                      result: result,
                      userask: results[0].ask_time,
                      useranswer: results[0].answer_time,
                      ask: 0,
                      answer: answernew[0].ask_answertime
                    });
                  } else{
                    logging(4);
                    res.render('mypage.ejs',{
                      user_id: req.session.userid,
                      name: req.session.name,
                      provider: prov,
                      created_at: req.session.date,
                      result: result,
                      userask: results[0].ask_time,
                      useranswer: results[0].answer_time,
                      ask: 0,
                      answer: 0
                    });
                  }
                }
              }
            });
          }
        });
      });
    });
    logging(now() + ' : 마이페이지에 접속하였습니다.');
  } else{
    logging(now() + ' : 허가받지 않은 사용자가 마이페이지에 접속하였습니다.');
    res.send("<script>alert('로그인이 필요합니다!');location.href='/login';</script>");
  }
});

// 공고 삭제
app.get('/delete/:id', function(req, res, next){
  var id = req.params.id;

  var sql = 'DELETE FROM post WHERE id=?';
  client.query(sql, [id], function(err, row){  // 해당 파라미터 값을 기본키로 갖고있는 공고 삭제
    logging(now() + ' : '+ id + '번 째 공고를 삭제하였습니다.');
    res.send("<script>alert('공고를 삭제하였습니다!');location.href='/mypage';</script>");
  });
});

// 공고 수정
app.get('/edit/:id', function(req, res, next){
  var id = req.params.id;

  var sql = 'SELECT id, auth, date, title, content, category, count, file, deadline from post where id=?';
  client.query(sql, [id], function(err, row){
    if(row[0].deadline<now()){  // 이미 마감일이 지나가 입찰 목록을 확인할 수 있게 된 공고는 수정 불가능
      res.send("<script>alert('이미 마감일이 지나간 공고는 수정할 수 없습니다!');location.href='/mypage';</script>");
    } else{
      f = row[0].file;
      fi = f.split('/');
      file = fi[2];
      res.render('edit', {
        row: row[0],
        file: file
      });
    }
  });
});

// 공고 수정 상세페이지
app.post('/edit/:id', upload.single('file'), (req, res) => {
  logging('수정 페이지 접속');
  var id = req.body.id;
  var title = req.body.title;
  var content = req.body.content;
  var category = req.body.category;
  var name = req.file.filename;
  var file = `/files/${name}`;
  var deadline = req.body.date + ' ' + req.body.time+':00';

  let orgFilename  = req.file.filename;
  let extension    = orgFilename.substr(-4, 4);  // 파일 확장자 ==> txt, jpg, png, mp4 암호화 및 복호화 OK
  let filename     = orgFilename.replace(extension, '');  // 원본 파일
  let orgfilePath  = 'files/';    // 원본 파일 경로
  let encrfilePath = 'encFiles/'; // 암호화 파일 저장 경로
  let decrfilePath = 'decFiles/'; // 복호화 파일 저장 경로

  let orgPathNfile = orgfilePath  + orgFilename;  // 원본 파일 경로+파일명
  let encrPathNfile= encrfilePath + filename + '.crypt'; // 암호화 파일 경로+파일명 저장용

  console.log("원 본 폴더: ", orgfilePath);
  console.log("원 본 파일: ", orgPathNfile);
  console.log("암호화폴더: ", encrfilePath);
  console.log("암호화파일: ", encrPathNfile);

  // 암호화 저장
  if (fs.existsSync(encrPathNfile)) {  // 암호화 키로 파일 암호화, 암호화 파일이 있으면 에러발생, 검사-삭제후 실행코드 필요!!
     console.log("기존 암호화 파일 삭제 ");
     fs.unlink(encrPathNfile, function() {}); // 암호화 파일 존재시 삭제
  }
  let f = new encrypt.FileEncrypt(orgPathNfile, encrfilePath, '.crypt', false); // false=파일명 변경 안함, true=무작위 파일명 생성
  f.openSourceFile();
  f.encrypt(key);
  encrPathNfile = f.encryptFilePath;  // 암호화된 새 파일명(경로포함) 저장
  console.log("encrypt sync done");

  fs.unlink(orgPathNfile, function() {}); // 암호화 전 파일 삭제

  if(deadline < now()){
    logging(now() + ' : 날짜 입력 오류!');
    res.send("<script>alert('잘못된 개찰일 설정입니다.');location.href='/mypage';</script>");
  }else{
    client.query('UPDATE post SET date=?, title=?, content=?, category=?, file=?, deadline=?, filememe=? WHERE id=?', [now(), title, content, category, encrPathNfile, deadline, extension, id], function(err, result){
      if(err){
        logging(now() + ' : 공고 작성 DB 오류!');
        res.send("<script>alert('오류');location.href='/mypage';</script>");
      }else{
      logging(now() + ' : 글이 수정되었습니다.');
      res.send("<script>location.href='/mypage';</script>");
    }
  });
}});

// 로그인 안 한 채로 인가가 필요한 페이지에 접속하였을 경우, 로그인 요청
app.get('/plzlogin', function(req, res, next){
  res.render('plzlogin.ejs');
  logging(now() + ' : 로그인 하지 않은 사용자가 접속을 시도하였습니다..');
});

// 개찰 결과 등록 페이지
app.get('/opening', function(req, res, next){
  var order = ' ORDER BY';
  var day = ' date';
  var dead = ' deadline';
  var latest = ' ASC';
  var recent = ' DESC';

  var sql = 'SELECT * FROM post WHERE auth=? AND deadline<?';

  if(req.query.day == 'day_recent'){  // 입찰 목록 정렬 선택
    sql = sql + order + day + recent;
  } else if (req.query.day == 'dead_recent') {
    sql = sql + order + dead + recent;
  } else if (req.query.day == 'dead_latest') {
    sql = sql + order + dead + latest;
  } else if(req.query.day == 'day_latest'){
    sql = sql + order + day + latest;
  } else{
    sql = sql + order + day + recent;
  }

  if(req.session.loggedin == true){
    client.query(sql, [req.session.name, now()],function(err, result){
      if(err){
        logging(now() + ' : DB 오류 발생.');
        res.send("<script>alert('오류');location.href='/home';</script>");
      } else{
        logging(sql);
        res.render('opening.ejs', {
          result: result
        });
        logging(now() + ' : 개찰 결과 등록 페이지에 접속하였습니다.');
      }
    });
  } else{
    logging(now() + ' : 허가받지 않은 사용자가 개찰 결과 등록 페이지에 접속하였습니다.');
    res.send("<script>alert('로그인이 필요합니다!');location.href='/login';</script>");
  }
});

// 개찰 등록 페이지
app.get('/open/:id', function(req, res, next){  // id == post의 기본키인 id
  var id = req.params.id;

  if(req.session.loggedin == true){
    var sql = 'SELECT * FROM bidding WHERE post_id=?';

    if(req.query.day == 'day_recent'){  // 정렬 선택
      sql = sql + ' ORDER BY bid_time DESC';
    } else if (req.query.day == 'day_latest') {
      sql = sql + ' ORDER BY bid_time ASC';
    } else if (req.query.day == 'highprice') {
      sql = sql + ' ORDER BY bid_price DESC';
    } else if(req.query.day == 'lowprice'){
      sql = sql + ' ORDER BY bid_price ASC';
    } else{
      sql = sql + ' ORDER BY bid_time DESC';
    }

    client.query(sql, [id], function(err, result){  // 입찰 목록 출력
      if(result.length != 0){
        var sqlpost = 'SELECT title FROM post WHERE id=?';
        client.query(sqlpost, [id], function(err, data){
          f = result[0].bid_file;
          fi = f.split('\\');
          fil = fi[1];
          file = fil.split('.');

          var t = JSON.stringify(data[0]);
          var title = t.substring(10, t.length-2);

          var already = 0;

          for(var i = 0; i < result.length; i++){  // 이미 개찰된 적 있으면 개찰 할 수 없도록 함
            if(result[i].bid_select == 1){
              already++;
            }
          }
          if(already > 0){
            res.send("<script>alert('이미 개찰된 공고입니다! 개찰 결과를 등록할 수 없습니다.');location.href='/opening';</script>");
            logging(now() + ' : 이미 개찰된 공고입니다.');
          } else{
            res.render('open.ejs',{
              result: result,
              title: title+'의',
              file: file[0],
              id: id
            });
          }
        });
      } else {
        res.render('notopen.ejs');
        logging(now() + ' : 아직 입찰이 없습니다.');
      }
    });
    logging(now() + ' : 입찰 현황 페이지에 접속하였습니다.');

  } else{
    logging(now() + ' : 허가받지 않은 사용자가 개찰 결과 등록 페이지에 접속하였습니다.');
    res.send("<script>alert('로그인이 필요합니다!');location.href='/login';</script>");
  }
});

app.post('/open/:id', function(req, res, next){
  var post_id = req.params.id;
  var deadline = req.body.date + ' ' + req.body.time+':00';

  var searchsql = 'SELECT * FROM post where id=?';
  client.query(searchsql, [post_id], function(err, result){
    if(err){
      console.log('DB오류');
    } else{
      var re_bid = result[0].re_bid + 1;
      var auth = result[0].auth;
      var title = result[0].title;
      var content = result[0].content;
      var category = result[0].category;
      var file = result[0].file;
      var filememe = result[0].filememe;

      var sql = 'INSERT INTO post(auth, date, title, content, category, count, file, deadline, filememe, re_bid) VALUES(?, ?, ?, ?, ?, 0, ?, ?, ?, ?)';
      var datas = [auth, now(), title, content, category, file, deadline, filememe, re_bid];
      client.query(sql, datas, function(err, results){
        if(err){
          console.log('DB오류');
        } else{
          res.redirect('/mypage');
        }
      });
    }
  });
});

// 개찰 결과 선택 시
app.get('/bidselect/:post_id/:id', function(req, res, next){  // post_id는 post의 기본키, id는 bidding의 기본키
  var bid_id = req.params.id;
  var post_id = req.params.post_id;

  var sql = 'SELECT bid_select FROM bidding WHERE post_id=?';
  client.query(sql, [post_id], function(err, result){
    if(err){
      logging('오류1');
    } else{
      var sqlbid = 'UPDATE bidding SET bid_select=1 WHERE id=?';
      client.query(sqlbid, [bid_id], function(err, data){
        if(err){
          logging('오류2');
        } else {
          res.send("<script>alert('낙찰하였습니다! 개찰 결과에 표시됩니다.');location.href='/opening';</script>");
          logging(now() + ' : ' + bid_id + '번째 입찰이 선택되었습니다. 개찰 결과에 표시됩니다.');
        }
      });
    }
  });
});

// 개찰 결과 열람 페이지
app.get('/bidOpen', function(req, res, next){
  if(req.session.loggedin == true){
    var sql = 'SELECT * FROM bidding WHERE auth_id=? ORDER BY bid_time DESC';
    client.query(sql, [req.session.idnum], function(err, result){  // 자신이 참여한 입찰 목록 출력
      if(result[0]){
        f = result[0].bid_file;
        fi = f.split('\\');
        fil = fi[1];
        file = fil.split('.');

        res.render('bidOpen.ejs',{
          result: result,
          file: file[0]
        });
      }else{
        logging(now() + ' : 아직 참여한 입찰이 없습니다.');
        res.send("<script>alert('아직 참여한 입찰이 없습니다.');location.href='/posting';</script>");
      }
    });
    logging(now() + ' : 개찰결과 열람 페이지에 접속하였습니다.');
  } else{
    logging(now() + ' : 허가받지 않은 사용자가 개찰 열람 페이지에 접속하였습니다.');
    res.send("<script>alert('로그인이 필요합니다!');location.href='/login';</script>");
  }
});

// 해당 입찰의 공고가 개찰되었는지 확인
app.get('/bidOpen/:post_id/:id', function(req, res, next){
  var post_id = req.params.post_id;
  var id = req.params.id;

  if(req.session.loggedin == true){
    var sql = 'SELECT * FROM post WHERE id=?';
    client.query(sql, [post_id], function(err, result){
      if(err){
        logging('오류1');
      } else{
        var sqlbid = 'SELECT * FROM bidding WHERE id=?';
        client.query(sqlbid, [id], function(err, results){
          if(err){
            logging('오류2');
          } else{
            var sqlselect = 'SELECT * FROM bidding WHERE post_id=?';
            client.query(sqlselect, [post_id], function(err, data){
              if(err){
                logging('오류3');
              } else{
                var select = 0;  // 해당 공고에 등록된 입찰들 중 선택 된 것이 있는지 확인
                for(var i = 0; i < data.length; i++){
                  if(data[i].bid_select == 1){
                    select++;
                  }
                }
                if(select > 0){
                  f = result[0].file;
                  fi = f.split('\\');
                  fil = fi[1];
                  file = fil.split('.');

                  logging(now() + ' : 개찰결과 확인 페이지에 접속하였습니다.');
                  res.render('bidOpenpage.ejs',{
                    result: result[0],
                    results: results[0],
                    file: file[0],
                    post_id: post_id
                  });
                } else {
                  logging(now() + ' : 아직 개찰이 완료되지 않았습니다.');
                  res.send("<script>alert('아직 개찰이 완료되지 않았습니다.');location.href='/bidOpen';</script>");
                }
              }
            });
          }
        });
      }
    });
  } else{
    logging(now() + ' : 허가받지 않은 사용자가 개찰 확인 페이지에 접속하였습니다.');
    res.send("<script>alert('로그인이 필요합니다!');location.href='/login';</script>");
  }
});

// 입찰 신청 페이지
app.get('/bid/:id', function(req, res, next){
  var id = req.params.id;
  if(req.session.loggedin == true){
    var sql = 'SELECT id, auth, date, title, content, category, count, file, deadline from post where id=?';
    client.query(sql, [id], function(err, row){
      logging(row[0].deadline);
      if(row[0].deadline > now()){  // 마감일 전이면 입찰 진행. 마감일 지났으면 거부
        if(row[0].auth == req.session.name){
          logging(now() + ' : 자신이 올린 공고에 입찰을 신청하였습니다..');
          res.send("<script>alert('자신이 올린 공고에는 입찰 신청할 수 없습니다.');location.href='/posting';</script>");
        } else{
          res.render('bid', {
            row: row[0]
          });
        }
      }else{
        logging(now() + ' : 입찰이 마감된 공고입니다.');
        res.send("<script>alert('입찰이 마감된 공고입니다.');location.href='/posting';</script>");
      };
    });
  } else{
    logging(now() + ' : 허가받지 않은 사용자가 입찰 페이지에 접속하였습니다.');
    res.send("<script>alert('로그인이 필요합니다!');location.href='/login';</script>");
  }
});

app.post('/bid/:id', upload.single('bid_file'), (req, res)=>{
  var post_id = req.body.id;
  var auth_id = req.session.idnum;

  var bid_firm = req.body.bid_firm;
  var bid_ceo = req.body.bid_ceo;
  var bid_price = req.body.bid_price;
  var bid_etc = req.body.bid_etc;
  var bid_file = `/files/${req.file.filename}`;

  let orgFilename  = req.file.filename;
  let extension    = orgFilename.substr(-4, 4);  // 파일 확장자 ==> txt, jpg, png, mp4 암호화 및 복호화 OK
  let filename     = orgFilename.replace(extension, '');  // 원본 파일
  let orgfilePath  = 'files/';    // 원본 파일 경로
  let encrfilePath = 'encFiles/'; // 암호화 파일 저장 경로
  let decrfilePath = 'decFiles/'; // 복호화 파일 저장 경로

  let orgPathNfile = orgfilePath  + orgFilename;  // 원본 파일 경로+파일명
  let encrPathNfile= encrfilePath + filename + '.crypt'; // 암호화 파일 경로+파일명 저장용

  console.log("원 본 폴더: ", orgfilePath);
  console.log("원 본 파일: ", orgPathNfile);
  console.log("암호화폴더: ", encrfilePath);
  console.log("암호화파일: ", encrPathNfile);

  // 암호화 저장
  if (fs.existsSync(encrPathNfile)) {  // 암호화 키로 파일 암호화, 암호화 파일이 있으면 에러발생, 검사-삭제후 실행코드 필요!!
     console.log("기존 암호화 파일 삭제 ");
     fs.unlink(encrPathNfile, function() {}); // 암호화 파일 존재시 삭제
  }
  let f = new encrypt.FileEncrypt(orgPathNfile, encrfilePath, '.crypt', false); // false=파일명 변경 안함, true=무작위 파일명 생성
  f.openSourceFile();
  f.encrypt(key);
  encrPathNfile = f.encryptFilePath;  // 암호화된 새 파일명(경로포함) 저장
  console.log("encrypt sync done");

  fs.unlink(orgPathNfile, function() {}); // 암호화 전 파일 삭제

  var datas = [post_id, auth_id, bid_firm, bid_ceo, bid_price, encrPathNfile, now(), bid_etc, extension];
  var sql = 'INSERT INTO bidding(post_id, auth_id, bid_firm, bid_ceo, bid_price, bid_file, bid_time, bid_etc, bid_filememe) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)';
  client.query(sql, datas, function(err, result){
    if(err){
      logging(now() + ' : 입찰 신청 DB 오류!');
      res.send("<script>alert('오류');location.href='/posting';</script>");
    } else{
      res.redirect('/posting');
    }
  });
});

// 공지 상세 페이지
app.get('/noticePosts1', function(req, res, next){
  res.render('noticePosts1.ejs');
});
app.get('/noticePosts2', function(req, res, next){
  res.render('noticePosts2.ejs');
});
app.get('/noticePosts3', function(req, res, next){
  res.render('noticePosts3.ejs');
});
app.get('/noticePosts4', function(req, res, next){
  res.render('noticePosts4.ejs');
});
// FAQ 상세 페이지
app.get('/A1', function(req, res, next){
  res.render('A1.ejs');
});
app.get('/A2', function(req, res, next){
  res.render('A2.ejs');
});
app.get('/A3', function(req, res, next){
  res.render('A3.ejs');
});

// 문의 열람 페이지
app.get('/ask/:post_id', function(req, res, next){
  var post_id = post_id;
  logging(post_id);
  res.render('ask.ejs',{
    post_id: post_id
  });
});

app.post('/ask/:post_id', upload.single('file'), function(req, res, next){
  var ask_postid = req.params.post_id;
  var ask_auth = req.session.name;
  var ask_date = now();
  var ask_title = req.body.ask_title;
  var ask_content = req.body.ask_content;
  logging(req.file);

  if(req.file){
    logging('파일 있음')
    var ask_askfile = `/files/${req.file.filename}`;
    let orgFilename  = req.file.filename;
    let extension    = orgFilename.substr(-4, 4);  // 파일 확장자 ==> txt, jpg, png, mp4 암호화 및 복호화 OK
    let filename     = orgFilename.replace(extension, '');  // 원본 파일
    let orgfilePath  = 'files/';    // 원본 파일 경로
    let encrfilePath = 'encFiles/'; // 암호화 파일 저장 경로
    let decrfilePath = 'decFiles/'; // 복호화 파일 저장 경로

    let orgPathNfile = orgfilePath  + orgFilename;  // 원본 파일 경로+파일명
    let encrPathNfile= encrfilePath + filename + '.crypt'; // 암호화 파일 경로+파일명 저장용

    console.log("원 본 폴더: ", orgfilePath);
    console.log("원 본 파일: ", orgPathNfile);
    console.log("암호화폴더: ", encrfilePath);
    console.log("암호화파일: ", encrPathNfile);

    // 암호화 저장
    if (fs.existsSync(encrPathNfile)) {  // 암호화 키로 파일 암호화, 암호화 파일이 있으면 에러발생, 검사-삭제후 실행코드 필요!!
       console.log("기존 암호화 파일 삭제 ");
       fs.unlink(encrPathNfile, function() {}); // 암호화 파일 존재시 삭제
    }
    let f = new encrypt.FileEncrypt(orgPathNfile, encrfilePath, '.crypt', false); // false=파일명 변경 안함, true=무작위 파일명 생성
    f.openSourceFile();
    f.encrypt(key);
    encrPathNfile = f.encryptFilePath;  // 암호화된 새 파일명(경로포함) 저장
    console.log("encrypt sync done");

    fs.unlink(orgPathNfile, function() {}); // 암호화 전 파일 삭제

    var sqlpost = 'SELECT auth FROM post WHERE id=?';
    client.query(sqlpost, [ask_postid], function(err, auth){
      if(err){
        logging('DB오류1');
      } else{
        var ask_postauth = auth[0];
        ask_postauth = ask_postauth.auth;
        var sql = 'INSERT INTO ask(ask_postid, ask_postauth, ask_auth, ask_date, ask_title, ask_content, ask_askfile, ask_askfilememe) VALUES(?, ?, ?, ?, ?, ?, ?, ?)';
        client.query(sql, [ask_postid, ask_postauth, ask_auth, ask_date, ask_title, ask_content, encrPathNfile, extension], function(err, result){
          if(err){
            logging('DB오류2');
          }else{
            res.send("<script>alert('성공적으로 문의를 등록하였습니다!');location.href='/bidOpen';</script>");
          }
        });
      }
    });
  } else{
    logging('파일 없음')
    var sqlpost = 'SELECT auth FROM post WHERE id=?';
    client.query(sqlpost, [ask_postid], function(err, auth){
      if(err){
        logging('DB오류1');
      } else{
        var ask_postauth = auth[0];
        ask_postauth = ask_postauth.auth;
        var sql = 'INSERT INTO ask(ask_postid, ask_postauth, ask_auth, ask_date, ask_title, ask_content) VALUES(?, ?, ?, ?, ?, ?)';
        client.query(sql, [ask_postid, ask_postauth, ask_auth, ask_date, ask_title, ask_content], function(err, result){
          if(err){
            logging('DB오류2');
          }else{
            res.send("<script>alert('성공적으로 문의를 등록하였습니다!');location.href='/bidOpen';</script>");
          }
        });
      }
    });
  }
});

// 답변 목록 페이지
app.get('/answer', function(req, res, next){
  var name = req.session.name;
  var id = req.session.idnum;
  logging(id);

  var answertime = 'UPDATE user SET ask_time=? WHERE id=?';
  client.query(answertime, [now(), id], function(err, results){
    if(err){
      logging('DB오류');
    }else{
      var sql = 'SELECT * FROM ask WHERE ask_postauth=? ORDER BY ask_date DESC';
      client.query(sql, [name], function(err, result){
        if(err){
          logging('DB 오류!');
        } else{
          res.render('answer.ejs', {
            result: result
          });
        }
      });
    }
  });
});

// 답변 상세 페이지
app.get('/answer/:id', function(req, res, next){
  var post_id = req.params.id;

  var sql = 'SELECT * FROM ask WHERE ask_id=?';
  client.query(sql, [post_id], function(err, result){
    if(err){
      logging('DB 오류!');
    } else{
      if(result[0].ask_askfile){
        f = result[0].ask_askfile;
        fi = f.split('\\');
        fil = fi[1];
        file = fil.split('.');
        if(result[0].ask_answerfile){
          a = result[0].ask_answerfile;
          af = a.split('\\');
          afi = af[1];
          answerfile = afi.split('.');
          res.render('answerPost.ejs', {
            result: result[0],
            file: file[0],
            answerfile: answerfile[0]
          });
        } else{
          res.render('answerPost.ejs', {
            result: result[0],
            file: file[0],
            answerfile: 0
          });
        }
      } else{
        if(result[0].ask_answerfile){
          a = result[0].ask_answerfile;
          af = a.split('\\');
          afi = af[1];
          answerfile = afi.split('.');
          res.render('answerPost.ejs', {
            result: result[0],
            file: 0,
            answerfile: answerfile[0]
          });
        } else{
          res.render('answerPost.ejs', {
            result: result[0],
            file: 0,
            answerfile: 0
          });
        }
      }
    }
  });
});

// 답변 작성 페이지
app.get('/answering/:id', function(req, res, next){
  var post_id = req.params.id;

  res.render('answering.ejs',{
    post_id: post_id
  });
});

app.post('/answering/:id', upload.single('file'), function(req, res, next){
  var post_id = req.params.id;
  var ask_answer = req.body.ask_content;

  if(req.file){
    var aks_answerfile = `/files/${req.file.filename}`;
    let orgFilename  = req.file.filename;
    let extension    = orgFilename.substr(-4, 4);  // 파일 확장자 ==> txt, jpg, png, mp4 암호화 및 복호화 OK
    let filename     = orgFilename.replace(extension, '');  // 원본 파일
    let orgfilePath  = 'files/';    // 원본 파일 경로
    let encrfilePath = 'encFiles/'; // 암호화 파일 저장 경로
    let decrfilePath = 'decFiles/'; // 복호화 파일 저장 경로

    let orgPathNfile = orgfilePath  + orgFilename;  // 원본 파일 경로+파일명
    let encrPathNfile= encrfilePath + filename + '.crypt'; // 암호화 파일 경로+파일명 저장용

    console.log("원 본 폴더: ", orgfilePath);
    console.log("원 본 파일: ", orgPathNfile);
    console.log("암호화폴더: ", encrfilePath);
    console.log("암호화파일: ", encrPathNfile);

    // 암호화 저장
    if (fs.existsSync(encrPathNfile)) {  // 암호화 키로 파일 암호화, 암호화 파일이 있으면 에러발생, 검사-삭제후 실행코드 필요!!
       console.log("기존 암호화 파일 삭제 ");
       fs.unlink(encrPathNfile, function() {}); // 암호화 파일 존재시 삭제
    }
    let f = new encrypt.FileEncrypt(orgPathNfile, encrfilePath, '.crypt', false); // false=파일명 변경 안함, true=무작위 파일명 생성
    f.openSourceFile();
    f.encrypt(key);
    encrPathNfile = f.encryptFilePath;  // 암호화된 새 파일명(경로포함) 저장
    console.log("encrypt sync done");

    fs.unlink(orgPathNfile, function() {}); // 암호화 전 파일 삭제

    var sql = 'UPDATE ask SET ask_answer=?, ask_answerfile=?, ask_answerfilememe=?, ask_answertime=? WHERE ask_id=?';
    client.query(sql, [ask_answer, encrPathNfile, extension, now(), post_id], function(err, result){
      if(err){
        logging('DB오류!');
      } else{
        res.send("<script>alert('성공적으로 문의 답변을 등록하였습니다!');location.href='/answer';</script>");
      }
    });
  } else{
    var sql = 'UPDATE ask SET ask_answer=?, ask_answertime=? WHERE ask_id=?';
    client.query(sql, [ask_answer, now(), post_id], function(err, result){
      if(err){
        logging(ask_answer);
        logging(now());
        logging(post_id);
        logging(result);
        logging('DB오류!');
      } else{
        res.send("<script>alert('성공적으로 문의 답변을 등록하였습니다!');location.href='/answer';</script>");
      }
    });
  }
});

// 내 문의 목록 페이지
app.get('/myask', function(req, res, next){
  var name = req.session.name;
  var id = req.session.idnum;

  var asktime = 'UPDATE user SET answer_time=? WHERE id=?';
  client.query(asktime, [now(), id], function(err, results){
    if(err){
      logging('DB오류');
    } else{
      var sql = 'SELECT * FROM ask WHERE ask_auth=? ORDER BY ask_date DESC';
      client.query(sql, [name], function(err, result){
        if(err){
          logging('DB 오류!');
        } else{
          res.render('myask.ejs', {
            result: result
          });
        }
      });
    }
  });
});

// 내 문의 상세 확인 페이지
app.get('/myaskpost/:id', function(req, res, next){
  var post_id = req.params.id;

  var sql = 'SELECT * FROM ask WHERE ask_id=?';
  client.query(sql, [post_id], function(err, result){
    if(err){
      logging('DB 오류!');
    } else{  // 파일 존재 여부에 따라
      if(result[0].ask_askfile){
        f = result[0].ask_askfile;
        fi = f.split('\\');
        fil = fi[1];
        file = fil.split('.');
        if(result[0].ask_answerfile){
          a = result[0].ask_answerfile;
          af = a.split('\\');
          afi = af[1];
          answerfile = afi.split('.');
          res.render('myaskpost.ejs', {
            result: result[0],
            file: file[0],
            answerfile: answerfile[0]
          });
        } else{
          res.render('myaskpost.ejs', {
            result: result[0],
            file: file[0],
            answerfile: 0
          });
        }
      } else{
        if(result[0].ask_answerfile){
          a = result[0].ask_answerfile;
          af = a.split('\\');
          afi = af[1];
          answerfile = afi.split('.');
          res.render('myaskpost.ejs', {
            result: result[0],
            file: 0,
            answerfile: answerfile[0]
          });
        } else{
          res.render('myaskpost.ejs', {
            result: result[0],
            file: 0,
            answerfile: 0
          });
        }
      }
    }
  });
});

// 개인정보 수정
app.get('/myedit', function(req, res){
  var idnum = req.session.idnum;

  var sql = 'SELECT * FROM user WHERE id=?';
  client.query(sql, [idnum], function(err, result){
    if(err){
      logging('오류!');
    }else{
      res.render('myedit.ejs', {
        result: result[0]
      });
    }
  });
});

app.post('/myedit', function(req, res, next){
  var ori_id = req.session.userid;
  var user_id = req.body.id;
  var ori_password = encryptionPW(req.body.p);
  var password = req.body.pw;
  var re_password = req.body.pwre;
  var name = req.body.name;
  var phone_num = req.body.txtMobile1 + '-' + req.body.txtMobile2 + '-' + req.body.txtMobile3;
  var provider = req.body.provider;

  var oripasscheck = 'SELECT * FROM user WHERE user_id=? AND password=?';
  var idcheck = 'SELECT * FROM user WHERE user_id=?';
  var namecheck = 'SELECT * FROM user WHERE name=?';

  // 모든 입력이 다 되어있는지 확인
  if(!ori_id || !user_id || !ori_password || !password || !re_password || !name || !phone_num || !provider){
    logging(now() + ' : 데이터 입력 값 부족으로 회원 정보 수정 실패!');
    res.send("<script>alert('값을 전부 입력해주세요.');location.href='/myedit';</script>");
  } else if(password != re_password) {
    // 패스워드와 재입력 값 비교
    logging(now() + ' : 패스워드 값이 서로 회원 정보 수정 실패!');
    res.send("<script>alert('비밀번호와 재입력 값이 다릅니다!');location.href='/myedit';</script>");
  } else{
    // 원래 패스워드가 맞는지 확인
    client.query(oripasscheck, [ori_id, ori_password], function(err, result){
      if(err){
        logging('DB오류!');
      } else{
        if(result[0]){
          // 유저 아이디가 중복이 아닌지 확인
          client.query(idcheck, [user_id], function(err, results){
            if(err){
              logging('오류');
            } else{
              if(results[0]){
                logging(now() + ' : 이미 존재하는 아이디를 입력하여 회원 정보 수정 실패!');
                res.send("<script>alert('이미 존재하는 아이디입니다, 다른 아이디로 설정해주세요!');location.href='/myedit';</script>");
              } else{
                // 이름이 중복이 아닌지 확인
                client.query(namecheck, [name], function(err, data){
                  if(err){
                    logging('오류!');
                  } else{
                    if(data[0]){
                      logging(now() + ' : 이미 존재하는 이름을 입력하여 회원 정보 수정 실패!');
                      res.send("<script>alert('이미 존재하는 이름입니다, 다른 이름으로 설정해주세요!');location.href='/myedit';</script>");
                    } else{
                      // 업데이트 시작
                      if (provider == "buyer") {  // 체크에 따라 구매자/공급자
                        provider = 0;
                      } else{
                        provider = 1;
                      }
                      var sql = 'UPDATE user SET user_id=?, password=?, name=?, provider=?, phone_num=? WHERE id=?';
                      var id = req.session.idnum;
                      var passwd = encryptionPW(password);
                      logging(id);
                      client.query(sql, [user_id, passwd, name, provider, phone_num, id], function(err, datas){
                        if(err){
                          logging('update 오류');
                        } else{
                          logging(now() + ' : 회원 정보가 수정되었습니다.');
                          req.session.userid = user_id;
                          req.session.name = name;
                          req.session.prov = provider;
                          res.send("<script>location.href='/mypage';</script>");
                        }
                      });
                    }
                  }
                });
              }
            }
          });
        } else{
          logging(now() + ' : 원래 패스워드가 달라 회원 정보 수정 실패!');
          res.send("<script>alert('기존 비밀번호를 확인하세요!');location.href='/myedit';</script>");
        }
      }
    })
  }
});

// 메일로 패스워드 재설정
app.get('/repassword', function(req, res){
  res.render('repassword.ejs');
});

app.post('/repassword', function(req, res, next){
  var user_id = req.body.id;

  var sql = 'SELECT * FROM user where user_id=?';

  client.query(sql, [user_id], function(err, result){
    if(err){
      logging(now() + ' : DB 오류 발생.');
      res.send("<script>alert('오류');location.href='/repassword';</script>");
    } else{
      if(result[0]){
        var mail = result[0].email;
        var randomPassword = createRandomPassword(variable, 8);

        var emailOptions = {
          from: 'ebsbidding@gmail.com',
          to: mail,
          subject: 'EBS 웹사이트 임시 비밀번호입니다.',
          html:
          "<h1 >EBS 웹사이트에서 새로운 비밀번호를 알려드립니다.</h1> <h2> 비밀번호 : " + randomPassword + "</h2>"
                      +'<h3 style="color: crimson;">임시 비밀번호로 로그인 하신 후, 반드시 비밀번호를 수정해 주세요.</h3>'
                      ,
        };
        transporter.sendMail(emailOptions, res);

        var password = encryptionPW(randomPassword);
        var pwsql = 'UPDATE user SET password=? WHERE user_id=?';

        client.query(pwsql, [password, user_id], function(err, results){
          if(err){
            logging(now() + ' : DB오류');
            res.send("<script>alert('DB오류.');location.href='/repassword';</script>");
          } else{
            logging(now() + ' : 메일 전송');
            res.send("<script>alert('메일을 전송하였습니다! 확인해주세요.');location.href='/login';</script>");
          }
        });
      } else{
        logging(now() + ' : 계정이 존재하지 않습니다.');
        res.send("<script>alert('계정이 존재하지 않습니다.');location.href='/repassword';</script>");
      }
    }
  })
});



// **************************  기타 설정 및 작동  *******************************

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error',{
    message: err.message,
    error: {}
  });
});

var http = require('http').Server(app);

// 서버 동작
http.listen(80, function(){
  console.log('server Running!! >> http://localhost:80');
});

//client.end();

module.exports = app;
