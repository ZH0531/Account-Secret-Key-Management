from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Request, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import asc, desc, case, func
from typing import List
from datetime import datetime, timedelta

from app.database import get_db
from app.models import Account, Key, AccountStatus, KeyStatus, KeyType
from app.schemas import (
    AccountResponse, KeyCreate, KeyResponse, StatsResponse
)
from app.auth import verify_admin, create_session, check_credentials
from app.utils import (
    generate_key_code, parse_account_file, 
    calculate_remaining_time, format_datetime
)
import os

INTERNAL_UPLOAD_TOKEN = os.getenv("INTERNAL_UPLOAD_TOKEN", "CHANGE_ME_INTERNAL_TOKEN")

router = APIRouter(prefix="/admin", tags=["管理端"])
templates = Jinja2Templates(directory="app/templates")

# ==================== 登录/登出 ====================

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """登录页面"""
    return templates.TemplateResponse("login.html", {"request": request})

@router.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    """登录处理"""
    if not check_credentials(username, password):
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    
    # 创建Session
    session_token = create_session(username)
    
    response = JSONResponse(content={"success": True})
    response.set_cookie(
        key="admin_session",
        value=session_token,
        httponly=True,
        max_age=86400,  # 24小时
        samesite="lax"
    )
    return response

@router.get("/logout")
async def logout():
    """登出"""
    response = RedirectResponse(url="/admin/login", status_code=302)
    response.delete_cookie("admin_session")
    return response

# ==================== 页面路由 ====================

@router.get("/", response_class=HTMLResponse)
async def admin_dashboard(request: Request, username: str = Depends(verify_admin), db: Session = Depends(get_db)):
    """管理仪表盘"""
    stats = get_statistics(db)
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "stats": stats
    })

@router.get("/keys", response_class=HTMLResponse)
async def keys_page(request: Request, username: str = Depends(verify_admin)):
    """密钥管理页面"""
    return templates.TemplateResponse("keys.html", {"request": request})

@router.get("/accounts", response_class=HTMLResponse)
async def accounts_page(request: Request, username: str = Depends(verify_admin)):
    """账号管理页面"""
    return templates.TemplateResponse("accounts.html", {"request": request})

# ==================== API接口 ====================

@router.get("/api/stats", response_model=StatsResponse)
async def get_stats(username: str = Depends(verify_admin), db: Session = Depends(get_db)):
    """获取统计信息"""
    return get_statistics(db)

@router.post("/api/keys/create")
async def create_keys(
    count: int,
    key_type: str,
    duration_days: int,
    notes: str = "",
    account_limit: int = 0,
    username: str = Depends(verify_admin),
    db: Session = Depends(get_db)
):
    """批量创建密钥"""
    if count <= 0 or count > 100:
        raise HTTPException(status_code=400, detail="数量必须在1-100之间")
    
    if key_type not in ["unlimited", "limited"]:
        raise HTTPException(status_code=400, detail="密钥类型必须为 unlimited 或 limited")
    
    if duration_days <= 0:
        raise HTTPException(status_code=400, detail="有效期必须大于0天")
    
    if account_limit < 0:
        raise HTTPException(status_code=400, detail="账号数量必顾不小于0（0 表示不限）")
    
    # 验证无限额度类型
    if key_type == "unlimited" and account_limit > 0:
        raise HTTPException(status_code=400, detail="无限额度类型的账号配额必须为0")
    
    # 验证有限额度类型
    if key_type == "limited" and account_limit == 0:
        raise HTTPException(status_code=400, detail="有限额度类型必须设置账号配额")
    
    keys = []
    for _ in range(count):
        key_code = generate_key_code()
        # 确保密钥唯一
        while db.query(Key).filter(Key.key_code == key_code).first():
            key_code = generate_key_code()
        
        key = Key(
            key_code=key_code,
            key_type=KeyType[key_type],
            duration_days=duration_days,
            notes=notes,
            account_limit=account_limit
        )
        db.add(key)
        keys.append(key_code)
    
    db.commit()
    
    return {
        "success": True,
        "count": len(keys),
        "keys": keys,
        "preview": "\n".join(keys)
    }

@router.get("/api/keys/export")
async def export_keys(
    status: str = None,
    username: str = Depends(verify_admin),
    db: Session = Depends(get_db)
):
    """导出密钥列表为txt文件"""
    query = db.query(Key)
    
    # 根据状态筛选
    if status:
        query = query.filter(Key.status == KeyStatus[status])
    
    keys = query.order_by(Key.created_at.desc()).all()
    
    if not keys:
        raise HTTPException(status_code=404, detail="没有密钥可导出")
    
    # 生成导出内容
    lines = []
    lines.append("=" * 80)
    lines.append(f"密钥列表导出")
    lines.append(f"导出时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"总数量: {len(keys)}")
    if status:
        lines.append(f"筛选状态: {status}")
    lines.append("=" * 80)
    lines.append("")
    
    for idx, key in enumerate(keys, 1):
        lines.append(f"密钥 {idx}:")
        lines.append(f"  代码: {key.key_code}")
        lines.append(f"  状态: {key.status.value}")
        lines.append(f"  有效期: {key.duration_days}天")
        lines.append(f"  创建时间: {key.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        if key.activated_at:
            lines.append(f"  激活时间: {key.activated_at.strftime('%Y-%m-%d %H:%M:%S')}")
        if key.expires_at:
            lines.append(f"  过期时间: {key.expires_at.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  请求次数: {key.request_count}")
        # 配额信息
        limit = key.account_limit or 0
        remaining = (max(limit - (key.request_count or 0), 0) if limit > 0 else -1)
        lines.append(f"  账号配额: {'不限' if limit == 0 else limit}")
        lines.append(f"  剩余额度: {'不限' if remaining == -1 else remaining}")
        if key.notes:
            lines.append(f"  备注: {key.notes}")
        lines.append("")
    
    content = "\n".join(lines)
    filename = f"keys_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    return Response(
        content=content.encode('utf-8'),
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )

@router.get("/api/keys/list")
async def list_keys(
    page: int = 1,
    page_size: int = 10,
    status: str = None,
    sort: str = None,
    search: str = None,
    activated_from: str = None,
    activated_to: str = None,
    key_type: str = None,
    username: str = Depends(verify_admin),
    db: Session = Depends(get_db)
):
    """获取密钥列表（分页，最多10/页）"""
    # 规范参数
    if page < 1:
        page = 1
    if page_size < 1:
        page_size = 10
    if page_size > 10:
        page_size = 10
    query = db.query(Key)
    
    if status:
        try:
            query = query.filter(Key.status == KeyStatus[status])
        except Exception:
            pass
    # 关键字搜索（密钥代码）
    if search:
        s = search.strip().lower()
        if s:
            query = query.filter(func.lower(Key.key_code).like(f"%{s}%"))
    
    # 类型过滤（limited/unlimited）
    if key_type:
        try:
            query = query.filter(Key.key_type == KeyType[key_type])
        except Exception:
            pass
    
    # 激活时间范围过滤（日期字符串 YYYY-MM-DD）
    from_dt = None
    to_dt_next = None
    if activated_from:
        try:
            from_dt = datetime.strptime(activated_from, "%Y-%m-%d")
        except Exception:
            from_dt = None
    if activated_to:
        try:
            to_dt = datetime.strptime(activated_to, "%Y-%m-%d")
            to_dt_next = to_dt + timedelta(days=1)
        except Exception:
            to_dt_next = None
    if from_dt is not None:
        query = query.filter(Key.activated_at.isnot(None), Key.activated_at >= from_dt)
    if to_dt_next is not None:
        query = query.filter(Key.activated_at.isnot(None), Key.activated_at < to_dt_next)
    
    # 计算总数
    total = query.count()
    
    # 分页查询与排序
    skip = (page - 1) * page_size

    order_by_clauses = []
    if sort:
        parts = [p.strip() for p in sort.split(',') if p.strip()]
        for part in parts:
            if ':' in part:
                field, direction = part.split(':', 1)
            else:
                field, direction = part, 'desc'
            direction = direction.lower()
            is_desc = direction != 'asc'
            col = None
            if field == 'duration_days':
                col = Key.duration_days
            elif field == 'activated_at':
                col = Key.activated_at
            elif field in ('remaining_time', 'expires_at'):
                col = Key.expires_at
            elif field == 'account_limit':
                # 无上限(0)在排序时作为最大值处理
                col = case((Key.account_limit == 0, 10**9), else_=Key.account_limit)
            elif field == 'remaining_accounts':
                # 有限额度：按剩余量排序；无限额度：作为最大值处理
                col = case((Key.account_limit > 0, (Key.account_limit - Key.request_count)), else_=10**9)
            elif field == 'request_count':
                col = Key.request_count
            elif field == 'created_at':
                col = Key.created_at
            elif field == 'key_type':
                # unlimited 优先或置前（0）/ limited 置后（1）
                col = case((Key.key_type == KeyType.unlimited, 0), else_=1)
            if col is not None:
                order_by_clauses.append(desc(col) if is_desc else asc(col))
    if not order_by_clauses:
        order_by_clauses = [desc(Key.created_at)]

    keys = query.order_by(*order_by_clauses).offset(skip).limit(page_size).all()
    
    # 添加剩余时间计算
    result = []
    for key in keys:
        key_dict = KeyResponse.from_orm(key).model_dump()
        # Enum 转字符串，确保前端拿到的是字符串
        try:
            key_dict['key_type'] = key.key_type.value if key.key_type else 'limited'
        except Exception:
            key_dict['key_type'] = 'limited'
        if key.expires_at:
            key_dict['remaining_time'] = calculate_remaining_time(key.expires_at)
        else:
            key_dict['remaining_time'] = "未激活"
        # 额度信息
        limit = key.account_limit or 0
        key_dict['account_limit'] = limit
        key_dict['remaining_accounts'] = (max(limit - (key.request_count or 0), 0) if limit > 0 else -1)
        result.append(key_dict)
    
    return {
        "keys": result,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size
    }

@router.get("/api/accounts/list")
async def list_accounts(
    page: int = 1,
    page_size: int = 20,
    status: str = None,
    sort: str = None,
    username: str = Depends(verify_admin),
    db: Session = Depends(get_db)
):
    """获取账号列表（分页）"""
    query = db.query(Account)
    
    if status:
        try:
            query = query.filter(Account.status == AccountStatus[status])
        except Exception:
            pass
    
    # 计算总数
    total = query.count()
    
    # 分页查询与排序
    skip = (page - 1) * page_size

    order_by_clauses = []
    if sort:
        parts = [p.strip() for p in sort.split(',') if p.strip()]
        for part in parts:
            if ':' in part:
                field, direction = part.split(':', 1)
            else:
                field, direction = part, 'desc'
            direction = direction.lower()
            is_desc = direction != 'asc'
            col = None
            if field == 'assigned_at':
                col = Account.assigned_at
            elif field == 'created_at':
                col = Account.created_at
            if col is not None:
                order_by_clauses.append(desc(col) if is_desc else asc(col))
    if not order_by_clauses:
        order_by_clauses = [desc(Account.created_at)]

    accounts = query.order_by(*order_by_clauses).offset(skip).limit(page_size).all()
    
    return {
        "accounts": [AccountResponse.from_orm(account).model_dump() for account in accounts],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size
    }

@router.post("/api/keys/toggle-disable/{key_id}")
async def toggle_key_disable(
    key_id: int,
    username: str = Depends(verify_admin),
    db: Session = Depends(get_db)
):
    """禁用或恢复密钥"""
    key = db.query(Key).filter(Key.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="密钥不存在")
    
    # 切换禁用状态
    key.is_disabled = not key.is_disabled
    db.commit()
    
    status_text = "已禁用" if key.is_disabled else "已恢复"
    return {
        "success": True,
        "message": f"密钥{status_text}",
        "is_disabled": key.is_disabled
    }

@router.post("/api/accounts/update-status/{account_id}")
async def update_account_status(
    account_id: int,
    status: str,
    username: str = Depends(verify_admin),
    db: Session = Depends(get_db)
):
    """手动修改账号状态"""
    # 验证状态值
    if status not in ["unused", "used", "expired"]:
        raise HTTPException(status_code=400, detail="无效的状态值，必须是 unused、used 或 expired")
    
    # 查找账号
    account = db.query(Account).filter(Account.id == account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="账号不存在")
    
    old_status = account.status.value
    
    # 更新状态
    account.status = AccountStatus[status]
    
    # 如果设置为已使用状态，更新分配时间
    if status == "used" and not account.assigned_at:
        account.assigned_at = datetime.utcnow()
    
    db.commit()
    
    return {
        "success": True,
        "message": f"账号状态已从 {old_status} 更新为 {status}",
        "account_id": account_id,
        "old_status": old_status,
        "new_status": status
    }

@router.post("/api/accounts/upload")
async def upload_accounts(
    files: List[UploadFile] = File(...),
    username: str = Depends(verify_admin),
    db: Session = Depends(get_db)
):
    """上传账号批量文件（支持多文件）"""
    total_accounts = 0
    success_count = 0
    duplicate_count = 0
    
    for file in files:
        if not file.filename.endswith('.txt'):
            continue  # 跳过非txt文件
        
        # 读取文件内容
        content = await file.read()
        content_str = content.decode('utf-8')
        
        # 解析账号
        accounts_data = parse_account_file(content_str)
        
        if not accounts_data:
            continue
        
        total_accounts += len(accounts_data)
        
        # 批量插入
        for acc_data in accounts_data:
            # 检查是否已存在
            existing = db.query(Account).filter(Account.email == acc_data['email']).first()
            if existing:
                duplicate_count += 1
                continue
            
            account = Account(
                email=acc_data['email'],
                name=acc_data['name'],
                password=acc_data['password'],
                api_key=acc_data['api_key']
            )
            db.add(account)
            success_count += 1
    
    db.commit()
    
    if total_accounts == 0:
        raise HTTPException(status_code=400, detail="未解析到有效账号")
    
    return {
        "success": True,
        "total": total_accounts,
        "success_count": success_count,
        "duplicate_count": duplicate_count
    }


@router.post("/internal/api/accounts/upload")
async def internal_upload_accounts(
    request: Request,
    files: List[UploadFile] = File(...),
    db: Session = Depends(get_db)
):
    token = request.headers.get("X-Internal-Token")
    if not token or token != INTERNAL_UPLOAD_TOKEN:
        raise HTTPException(status_code=401, detail="invalid internal token")

    total_accounts = 0
    success_count = 0
    duplicate_count = 0
    
    for file in files:
        if not file.filename.endswith('.txt'):
            continue
        
        content = await file.read()
        content_str = content.decode('utf-8')
        
        accounts_data = parse_account_file(content_str)
        
        if not accounts_data:
            continue
        
        total_accounts += len(accounts_data)
        
        for acc_data in accounts_data:
            existing = db.query(Account).filter(Account.email == acc_data['email']).first()
            if existing:
                duplicate_count += 1
                continue
            
            account = Account(
                email=acc_data['email'],
                name=acc_data['name'],
                password=acc_data['password'],
                api_key=acc_data['api_key']
            )
            db.add(account)
            success_count += 1
    
    db.commit()
    
    if total_accounts == 0:
        raise HTTPException(status_code=400, detail="未解析到有效账号")
    
    return {
        "success": True,
        "total": total_accounts,
        "success_count": success_count,
        "duplicate_count": duplicate_count
    }

# ==================== 辅助函数 ====================

def get_statistics(db: Session) -> StatsResponse:
    """获取统计信息"""
    total_accounts = db.query(Account).count()
    unused_accounts = db.query(Account).filter(Account.status == AccountStatus.unused).count()
    used_accounts = db.query(Account).filter(Account.status == AccountStatus.used).count()
    expired_accounts = db.query(Account).filter(Account.status == AccountStatus.expired).count()
    
    total_keys = db.query(Key).count()
    inactive_keys = db.query(Key).filter(Key.status == KeyStatus.inactive).count()
    active_keys = db.query(Key).filter(Key.status == KeyStatus.active).count()
    expired_keys = db.query(Key).filter(Key.status == KeyStatus.expired).count()
    
    return StatsResponse(
        total_accounts=total_accounts,
        unused_accounts=unused_accounts,
        used_accounts=used_accounts,
        expired_accounts=expired_accounts,
        total_keys=total_keys,
        inactive_keys=inactive_keys,
        active_keys=active_keys,
        expired_keys=expired_keys
    )
