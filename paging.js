exports.list = function(page, callback){
	pool.getConnection(function(err, conn){
		if(err){
			console.error('err',err);
		}
		var sql = "select * from board;";
		conn.query(sql, [], function(err, rows){
			if(err){
				console.error('err',err);
			}
			conn.query("select count(*) cnt from board", [], function(err, rows){
				if(err){ console.error('err',err); }
				console.log("rows", rows); //[{cnt:1}]
				var cnt = rows[0].cnt;
				var size = 10; // 보여줄 글의 수
				var begin = (page - 1) * size; // 시작 글
				var totalPage = Math.ceil(cnt/size);
				var pageSize = 10; // 링크 갯수
				var startPage = Math.floor((page-1)/pageSize)*pageSize+1;
				var endPage = startPage + (pageSize - 1);
				if(endPage > totalPage){
					endPage = totalPage;
				}
				var max = cnt - ((page-1)*size);
				conn.query("select num, title, content, passwd, DATE_FORMAT(regdate, '%Y-%m-%d %H:%i:%s') regdate, hit, reply, recmd, id from board order by num desc limit ?,?",[begin, size], function(err, rows){
					if(err){console.error('err',err);}
					console.log('rows',rows);
					var datas={
						title: "게시판 리스트",
						data: rows,
						page: page,
						pageSize: pageSize,
						startPage: startPage,
						endPage: endPage,
						totalPage: totalPage,
						max: max
					};
					conn.release();
					callback(datas);
				});
			});
    });
  });
}
